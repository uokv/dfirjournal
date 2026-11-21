using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace JournalTrace.Native
{
    public static class UsnJournalIntegrity
    {
        public enum Status
        {
            Clean,
            Detected,
            Inactive,
            Unverified
        }

        public sealed class Finding
        {
            public string Code { get; set; }
            public long Usn { get; set; }
            public string Timestamp { get; set; }
            public string Residual { get; set; }
            public string Formatted { get; set; }
        }

        public sealed class ScanResult
        {
            public Status Status { get; set; }
            public string Reason { get; set; }
            public bool Detected { get; set; }
            public long RecordsRead { get; set; }
            public long SlackCount { get; set; }
            public long TimeSkewCount { get; set; }
            public long ZeroedCount { get; set; }
            public long GapCount { get; set; }
            public long GapBytes { get; set; }
            public long HookCount { get; set; }
            public long OverlapCount { get; set; }
            public long RawZeroCount { get; set; }
            public long DecoyCount { get; set; }
            public long GhostBytes { get; set; }
            public int GhostRangeCount { get; set; }
            public long ActiveHoleBytes { get; set; }
            public int ActiveHoleCount { get; set; }
            public bool ZeroWipe { get; set; }
            public bool MaxMismatch { get; set; }

            public long SignalCount
            {
                get
                {
                    long total = SlackCount + TimeSkewCount + ZeroedCount + GapCount + HookCount + OverlapCount + RawZeroCount + DecoyCount;
                    if (GhostBytes > 0)
                        total++;
                    if (ActiveHoleBytes > 0)
                        total++;
                    if (ZeroWipe)
                        total++;
                    if (MaxMismatch)
                        total++;
                    for (int i = 0; i < Findings.Count; i++)
                    {
                        string code = Findings[i].Code;
                        if (code == "0xU0" || code == "0xU5")
                            total++;
                    }
                    return total;
                }
            }
            public List<Finding> Findings { get; set; }
            public List<string> ExtraLines { get; set; }

            public ScanResult()
            {
                Findings = new List<Finding>();
                ExtraLines = new List<string>();
                Reason = "";
            }
        }

        const long TimeToleranceTicks = 60L * 10000000L;
        const uint FileShareDelete = 0x00000004;

        struct RecordFields
        {
            public bool Ok;
            public uint RecLen;
            public ushort Major;
            public ushort NameLen;
            public ushort NameOff;
            public ushort HeaderLen;
            public long Usn;
            public long Timestamp;
        }

        sealed class TimeTracker
        {
            public long TimeA;
            public long TimeB;
            public long UsnB;
            public int Seen;
        }

        public static ScanResult ScanVolume(char volumeLetter, int maxPerCategory)
        {
            ScanResult result = new ScanResult();
            if (maxPerCategory < 1)
                maxPerCategory = 1;

            if (!char.IsLetter(volumeLetter))
                volumeLetter = 'C';
            char letter = char.ToUpperInvariant(volumeLetter);
            string volPath = @"\\.\" + letter + ":";

            IntPtr volume = Win32Api.CreateFile(
                volPath,
                Win32Api.GENERIC_READ,
                Win32Api.FILE_SHARE_READ | Win32Api.FILE_SHARE_WRITE | FileShareDelete,
                IntPtr.Zero,
                Win32Api.OPEN_EXISTING,
                Win32Api.FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);

            if (volume == new IntPtr(-1) || volume == IntPtr.Zero)
            {
                result.Status = Status.Unverified;
                result.Reason = "volume nao abriu (requer Administrador)";
                return result;
            }

            try
            {
                Win32Api.USN_JOURNAL_DATA journal;
                uint returned;
                bool queried = Win32Api.DeviceIoControl(
                    volume,
                    Win32Api.FSCTL_QUERY_USN_JOURNAL,
                    IntPtr.Zero,
                    0,
                    out journal,
                    Marshal.SizeOf(typeof(Win32Api.USN_JOURNAL_DATA)),
                    out returned,
                    IntPtr.Zero);

                if (!queried)
                {
                    result.Status = Status.Unverified;
                    result.Reason = "journal nao respondeu";
                    return result;
                }

                if (journal.UsnJournalID == 0 || journal.NextUsn <= 8 || journal.NextUsn <= journal.FirstUsn)
                {
                    result.Status = Status.Inactive;
                    result.Reason = "journal inativo";
                    return result;
                }

                Win32Api.READ_USN_JOURNAL_DATA_V1 request = new Win32Api.READ_USN_JOURNAL_DATA_V1();
                request.StartUsn = journal.FirstUsn;
                request.ReasonMask = 0xFFFFFFFF;
                request.ReturnOnlyOnClose = 0;
                request.Timeout = 0;
                request.BytesToWaitFor = 0;
                request.UsnJournalId = journal.UsnJournalID;
                request.MinMajorVersion = 2;
                request.MaxMajorVersion = 2;

                int requestSize = Marshal.SizeOf(typeof(Win32Api.READ_USN_JOURNAL_DATA_V1));
                IntPtr requestBuffer = Marshal.AllocHGlobal(requestSize);
                const int bufferSize = 1 << 20;
                IntPtr dataBuffer = Marshal.AllocHGlobal(bufferSize);

                try
                {
                    Marshal.StructureToPtr(request, requestBuffer, false);

                    bool readOk = true;
                    bool firstBatch = true;
                    bool emptyActive = false;
                    long oddOffset = 0;
                    TimeTracker tracker = new TimeTracker();
                    List<Finding> slack = new List<Finding>();
                    List<Finding> skew = new List<Finding>();
                    List<Finding> zeroed = new List<Finding>();
                    List<Finding> gaps = new List<Finding>();
                    List<Finding> overlaps = new List<Finding>();
                    List<Finding> hooks = new List<Finding>();
                    List<HookPoint> hookPoints = new List<HookPoint>();
                    long prevEnd = journal.FirstUsn;
                    bool firstSpan = true;

                    while (true)
                    {
                        uint bytesReturned;
                        bool ok = Win32Api.DeviceIoControl(
                            volume,
                            Win32Api.FSCTL_READ_USN_JOURNAL,
                            requestBuffer,
                            requestSize,
                            dataBuffer,
                            bufferSize,
                            out bytesReturned,
                            IntPtr.Zero);

                        if (!ok)
                        {
                            int error = Marshal.GetLastWin32Error();
                            if (error == (int)Win32Api.GetLastErrorEnum.ERROR_HANDLE_EOF)
                                break;
                            readOk = false;
                            result.Reason = "leitura do journal interrompida";
                            break;
                        }

                        if (firstBatch && bytesReturned <= sizeof(long))
                            emptyActive = true;
                        firstBatch = false;
                        if (bytesReturned <= sizeof(long))
                            break;

                        int count = (int)bytesReturned;
                        byte[] batch = new byte[count];
                        Marshal.Copy(dataBuffer, batch, 0, count);

                        long nextUsn = ReadInt64(batch, 0);
                        CollectHookPoints(batch, count, hookPoints);
                        int offset = sizeof(long);
                        while (offset + 8 <= count)
                        {
                            RecordFields record = ParseRecord(batch, offset, count - offset);
                            if (!record.Ok)
                                break;

                            result.RecordsRead++;
                            bool isZeroed = false;
                            if (record.Usn > 0)
                                NoteUsnSpan(record, ref prevEnd, ref firstSpan, result, gaps, overlaps, maxPerCategory);

                            if (record.Major == 2 && record.RecLen >= 60)
                            {
                                ulong fileReference = ReadUInt64(batch, offset + 8);
                                uint reason = ReadUInt32(batch, offset + 40);
                                if (record.NameLen == 0 || fileReference == 0 || record.Timestamp == 0 || reason == 0)
                                {
                                    isZeroed = true;
                                    result.ZeroedCount++;
                                    if (zeroed.Count < maxPerCategory)
                                    {
                                        string timestamp = FormatLocalTime(record.Timestamp);
                                        if (timestamp.Length == 0 && tracker.TimeB > 0)
                                        {
                                            string previous = FormatLocalTime(tracker.TimeB);
                                            if (previous.Length != 0)
                                                timestamp = "~" + previous;
                                        }
                                        zeroed.Add(MakeFinding("0xU3", record.Usn, timestamp, null));
                                    }
                                }
                                else
                                {
                                    CheckTimeSequence(tracker, record.Timestamp, record.Usn, result, skew, maxPerCategory);
                                }
                            }

                            if (record.HeaderLen != 0)
                            {
                                ulong nameEnd = (ulong)record.NameOff + record.NameLen;
                                ulong expected = (nameEnd + 7UL) & ~7UL;
                                if (record.NameOff != record.HeaderLen)
                                    oddOffset++;
                                if (nameEnd <= record.RecLen && !isZeroed && record.RecLen > expected)
                                {
                                    result.SlackCount++;
                                    if (slack.Count < maxPerCategory)
                                    {
                                        string residual = ExtractSlackResidual(batch, offset, (uint)nameEnd, record.RecLen);
                                        string timestamp = FormatLocalTime(record.Timestamp);
                                        slack.Add(MakeFinding("0xU1", record.Usn, timestamp, residual));
                                    }
                                }
                            }

                            offset += (int)record.RecLen;
                        }

                        if (nextUsn <= request.StartUsn)
                            break;

                        request.StartUsn = nextUsn;
                        Marshal.WriteInt64(requestBuffer, nextUsn);
                    }

                    NoteHookJump(hookPoints, result, hooks);

                    long journalSize = journal.NextUsn - journal.FirstUsn;
                    InspectStreams(letter, journal, result, maxPerCategory);

                    if (emptyActive)
                    {
                        if (journalSize > 0xA00000L)
                        {
                            Finding empty = new Finding();
                            empty.Code = "0xU5";
                            empty.Formatted = "0xU5 \u00b7 cache wipe \u00b7 " + journalSize + " bytes";
                            result.Findings.Add(empty);
                            result.Detected = true;
                            result.Status = Status.Detected;
                            return result;
                        }

                        if (result.Findings.Count == 0 && result.ExtraLines.Count == 0)
                        {
                            result.Status = Status.Clean;
                            return result;
                        }

                        result.Detected = true;
                        result.Status = Status.Detected;
                        return result;
                    }

                    AppendCategory(result, "0xUB", result.HookCount, hooks);

                    bool weakRead = !readOk || result.RecordsRead < 1000 || oddOffset * 100 > result.RecordsRead;
                    if (!weakRead)
                    {
                        AppendCategory(result, "0xU1", result.SlackCount, slack);
                        AppendCategory(result, "0xU2", result.TimeSkewCount, skew);
                        AppendCategory(result, "0xU3", result.ZeroedCount, zeroed);
                        AppendCategory(result, "0xU4", result.GapCount, gaps);
                        AppendCategory(result, "0xU7", result.OverlapCount, overlaps);
                        if (journalSize > 0x100000L && result.GapBytes >= 0x80000L && result.GapBytes * 10L > journalSize)
                        {
                            long pct10 = (result.GapBytes * 1000L) / journalSize;
                            result.ExtraLines.Add("0xU4 \u00b7 cobertura " + result.GapBytes + " / " + journalSize + " (" + (pct10 / 10) + "." + (pct10 % 10) + "%)");
                        }
                    }

                    if (weakRead && result.Findings.Count == 0 && result.ExtraLines.Count == 0)
                    {
                        result.Status = Status.Unverified;
                        if (result.Reason.Length == 0)
                            result.Reason = result.RecordsRead < 1000 ? "poucas entradas no journal" : "layout fora do padrao";
                        return result;
                    }

                    result.Detected = result.Findings.Count > 0 || result.ExtraLines.Count > 0;
                    result.Status = result.Detected ? Status.Detected : Status.Clean;
                    return result;
                }
                finally
                {
                    Marshal.FreeHGlobal(requestBuffer);
                    Marshal.FreeHGlobal(dataBuffer);
                }
            }
            finally
            {
                Win32Api.CloseHandle(volume);
            }
        }

        static void AppendCategory(ScanResult result, string code, long total, List<Finding> list)
        {
            for (int i = 0; i < list.Count; i++)
                result.Findings.Add(list[i]);

            if (total > list.Count)
                result.ExtraLines.Add(code + " \u00b7 (+" + (total - list.Count) + " registros)");
        }

        static Finding MakeFinding(string code, long usn, string timestamp, string residual)
        {
            Finding finding = new Finding();
            finding.Code = code;
            finding.Usn = usn;
            finding.Timestamp = timestamp ?? "";
            finding.Residual = residual ?? "";
            finding.Formatted = BuildLine(code, usn, finding.Timestamp, finding.Residual);
            return finding;
        }

        static void CheckTimeSequence(TimeTracker tracker, long currentTime, long currentUsn, ScanResult result, List<Finding> skew, int cap)
        {
            if (tracker.Seen >= 2)
            {
                bool shiftedBack = tracker.TimeB < tracker.TimeA - TimeToleranceTicks && currentTime >= tracker.TimeA - 10000000L;
                bool shiftedForward = tracker.TimeB > tracker.TimeA + TimeToleranceTicks
                    && currentTime < tracker.TimeB - TimeToleranceTicks
                    && currentTime >= tracker.TimeA;
                if (shiftedBack || shiftedForward)
                {
                    result.TimeSkewCount++;
                    if (skew.Count < cap)
                    {
                        long streamTime = shiftedBack ? tracker.TimeA : currentTime;
                        skew.Add(MakeFinding("0xU2", tracker.UsnB, FormatLocalTime(streamTime), null));
                    }
                }
            }

            tracker.TimeA = tracker.TimeB;
            tracker.TimeB = currentTime;
            tracker.UsnB = currentUsn;
            if (tracker.Seen < 2)
                tracker.Seen++;
        }

        static void NoteUsnSpan(RecordFields record, ref long prevEnd, ref bool firstSpan, ScanResult result, List<Finding> gaps, List<Finding> overlaps, int cap)
        {
            const long minSpan = 0x10000;
            if (!firstSpan && record.Usn > prevEnd)
            {
                long gap = record.Usn - prevEnd;
                if (gap > minSpan)
                {
                    result.GapCount++;
                    result.GapBytes += gap;
                    if (gaps.Count < cap)
                        gaps.Add(MakeFinding("0xU4", record.Usn, FormatLocalTime(record.Timestamp), "gap " + gap));
                }
            }
            else if (!firstSpan && record.Usn < prevEnd)
            {
                long back = prevEnd - record.Usn;
                if (back > minSpan)
                {
                    result.OverlapCount++;
                    if (overlaps.Count < cap)
                        overlaps.Add(MakeFinding("0xU7", record.Usn, FormatLocalTime(record.Timestamp), "ate 0x" + prevEnd.ToString("X")));
                }
            }

            long aligned = (record.RecLen + 7L) & ~7L;
            prevEnd = record.Usn + aligned;
            firstSpan = false;
        }

        struct HookPoint
        {
            public long Usn;
            public long Time;
        }

        static void CollectHookPoints(byte[] batch, int count, List<HookPoint> points)
        {
            int offset = sizeof(long);
            while (offset + 8 <= count && points.Count < 1000000)
            {
                uint recLen = ReadUInt32(batch, offset);
                if (recLen == 0 || offset + recLen > count)
                    break;

                if (offset + 0x28 <= count)
                {
                    HookPoint point = new HookPoint();
                    point.Usn = ReadInt64(batch, offset + 0x18);
                    point.Time = ReadInt64(batch, offset + 0x20);
                    points.Add(point);
                }

                offset += (int)recLen;
            }
        }

        static void NoteHookJump(List<HookPoint> points, ScanResult result, List<Finding> hooks)
        {
            if (points.Count < 2)
                return;

            points.Sort(delegate (HookPoint left, HookPoint right)
            {
                return left.Usn.CompareTo(right.Usn);
            });

            for (int i = 1; i < points.Count; i++)
            {
                long delta = points[i].Usn - points[i - 1].Usn;
                if (delta < 0x320)
                    continue;

                result.HookCount++;
                string timestamp = FormatLocalTime(points[i - 1].Time);
                Finding finding = MakeFinding("0xUB", points[i - 1].Usn, timestamp, "hook " + delta);
                if (timestamp.Length != 0)
                    finding.Formatted = "Hook USN Journal (" + timestamp + ")";
                hooks.Add(finding);
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFilePointerEx(IntPtr hFile, long distance, out long newPosition, uint moveMethod);

        static void InspectStreams(char letter, Win32Api.USN_JOURNAL_DATA journal, ScanResult result, int maxPerCategory)
        {
            string root = @"\\?\" + letter + @":\$Extend\$UsnJrnl:";
            InspectMax(root + "$Max", journal, result);
            InspectJournalData(root + "$J", journal, result, maxPerCategory);
        }

        static void InspectMax(string path, Win32Api.USN_JOURNAL_DATA journal, ScanResult result)
        {
            IntPtr handle = OpenBackupFile(path);
            if (handle == IntPtr.Zero)
                return;

            IntPtr buffer = Marshal.AllocHGlobal(32);
            try
            {
                uint read;
                if (!Win32Api.ReadFile(handle, buffer, 32, out read, IntPtr.Zero) || read < 16)
                    return;

                ulong diskMax = (ulong)Marshal.ReadInt64(buffer, 0);
                ulong diskDelta = (ulong)Marshal.ReadInt64(buffer, 8);
                bool sizeDiff = diskMax != journal.MaximumSize || diskDelta != journal.AllocationDelta;
                bool idDiff = false;
                bool lowDiff = false;
                ulong diskId = 0;
                long diskLow = 0;
                if (read >= 32)
                {
                    diskId = (ulong)Marshal.ReadInt64(buffer, 16);
                    diskLow = Marshal.ReadInt64(buffer, 24);
                    idDiff = diskId != journal.UsnJournalID;
                    lowDiff = diskLow != journal.LowestValidUsn;
                }

                if (!sizeDiff && !idDiff && !lowDiff)
                    return;

                result.MaxMismatch = true;
                StringBuilder line = new StringBuilder();
                line.Append("0xUA");
                if (sizeDiff)
                    line.Append(" \u00b7 $Max ").Append(diskMax).Append('/').Append(diskDelta).Append(" \u00b7 fsctl ").Append(journal.MaximumSize).Append('/').Append(journal.AllocationDelta);
                if (idDiff)
                    line.Append(" \u00b7 id ").Append(diskId).Append(" \u00b7 fsctl ").Append(journal.UsnJournalID);
                if (lowDiff)
                    line.Append(" \u00b7 lowest ").Append(diskLow).Append(" \u00b7 fsctl ").Append(journal.LowestValidUsn);
                Finding finding = new Finding();
                finding.Code = "0xUA";
                finding.Formatted = line.ToString();
                result.Findings.Add(finding);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
                Win32Api.CloseHandle(handle);
            }
        }

        static void InspectJournalData(string path, Win32Api.USN_JOURNAL_DATA journal, ScanResult result, int maxPerCategory)
        {
            if (journal.FirstUsn < 0 || journal.NextUsn <= journal.FirstUsn)
                return;

            IntPtr handle = OpenBackupFile(path);
            if (handle == IntPtr.Zero)
                return;

            try
            {
                bool ghostComplete;
                List<AllocatedSpan> before = QueryAllocatedRanges(handle, 0, journal.FirstUsn, out ghostComplete);
                if (ghostComplete || before.Count > 0)
                {
                    for (int i = 0; i < before.Count; i++)
                    {
                        long start = before[i].Offset;
                        long end = before[i].Offset + before[i].Length;
                        if (end > journal.FirstUsn)
                            end = journal.FirstUsn;
                        if (end <= start)
                            continue;
                        result.GhostBytes += end - start;
                        result.GhostRangeCount++;
                    }
                }

                if (result.GhostBytes > 0)
                {
                    Finding ghost = new Finding();
                    ghost.Code = "0xU9";
                    ghost.Formatted = "0xU9 \u00b7 ghost " + result.GhostBytes + " bytes \u00b7 " + result.GhostRangeCount + " ranges";
                    result.Findings.Add(ghost);
                }

                bool liveComplete;
                List<AllocatedSpan> live = QueryAllocatedRanges(handle, journal.FirstUsn, journal.NextUsn - journal.FirstUsn, out liveComplete);
                NoteActiveHole(live, liveComplete, journal.FirstUsn, journal.NextUsn, result);
                List<Finding> rawZeros = new List<Finding>();
                List<Finding> decoys = new List<Finding>();
                ZeroTracker zeros = new ZeroTracker();
                live.Sort(delegate (AllocatedSpan left, AllocatedSpan right)
                {
                    return left.Offset.CompareTo(right.Offset);
                });
                for (int i = 0; i < live.Count; i++)
                {
                    long start = live[i].Offset;
                    long end = live[i].Offset + live[i].Length;
                    if (start < journal.FirstUsn)
                        start = journal.FirstUsn;
                    if (end > journal.NextUsn)
                        end = journal.NextUsn;
                    WalkRawRange(handle, start, end, result, rawZeros, decoys, maxPerCategory, zeros);
                }

                CloseZeroRun(zeros);
                if (zeros.Big || zeros.PageRuns >= 4)
                {
                    result.ZeroWipe = true;
                    Finding wipe = new Finding();
                    wipe.Code = "0xUC";
                    if (zeros.Big)
                    {
                        wipe.Usn = zeros.BigOffset;
                        wipe.Formatted = "0xUC \u00b7 zeros " + zeros.BigLength + " @ 0x" + zeros.BigOffset.ToString("X");
                    }
                    else
                    {
                        wipe.Usn = zeros.FirstPageOffset;
                        wipe.Formatted = "0xUC \u00b7 zeros 4KB x" + zeros.PageRuns;
                    }
                    result.Findings.Add(wipe);
                }

                AppendCategory(result, "0xU6", result.RawZeroCount, rawZeros);
                AppendCategory(result, "0xU8", result.DecoyCount, decoys);
            }
            finally
            {
                Win32Api.CloseHandle(handle);
            }
        }

        struct AllocatedSpan
        {
            public long Offset;
            public long Length;
        }

        static void NoteActiveHole(List<AllocatedSpan> live, bool complete, long first, long next, ScanResult result)
        {
            if (!complete || next <= first)
                return;

            live.Sort(delegate (AllocatedSpan left, AllocatedSpan right)
            {
                return left.Offset.CompareTo(right.Offset);
            });

            long cursor = first;
            long missing = 0;
            int holes = 0;
            for (int i = 0; i < live.Count; i++)
            {
                long start = live[i].Offset;
                long end = start + live[i].Length;
                if (end <= cursor)
                    continue;
                if (start >= next)
                    break;
                if (start > cursor)
                {
                    long gapEnd = start < next ? start : next;
                    missing += gapEnd - cursor;
                    holes++;
                    cursor = gapEnd;
                }

                if (end > cursor)
                    cursor = end;
                if (cursor >= next)
                    break;
            }

            if (cursor < next)
            {
                missing += next - cursor;
                holes++;
            }

            if (missing <= 0)
                return;

            result.ActiveHoleBytes = missing;
            result.ActiveHoleCount = holes;
            Finding finding = new Finding();
            finding.Code = "0xUE";
            finding.Formatted = "0xUE \u00b7 hole " + missing + " bytes \u00b7 " + holes + " ranges";
            result.Findings.Add(finding);
        }

        static List<AllocatedSpan> QueryAllocatedRanges(IntPtr handle, long offset, long length, out bool complete)
        {
            List<AllocatedSpan> ranges = new List<AllocatedSpan>();
            complete = false;
            if (length <= 0)
            {
                complete = true;
                return ranges;
            }

            IntPtr input = Marshal.AllocHGlobal(16);
            IntPtr output = Marshal.AllocHGlobal(64 * 1024);
            try
            {
                long cursor = offset;
                long end = offset + length;
                while (cursor < end)
                {
                    Marshal.WriteInt64(input, 0, cursor);
                    Marshal.WriteInt64(input, 8, end - cursor);
                    uint returned;
                    bool ok = Win32Api.DeviceIoControl(
                        handle,
                        Win32Api.FSCTL_QUERY_ALLOCATED_RANGES,
                        input,
                        16,
                        output,
                        64 * 1024,
                        out returned,
                        IntPtr.Zero);
                    int error = Marshal.GetLastWin32Error();
                    if (!ok && error != 234)
                        return ranges;

                    int count = (int)returned / 16;
                    if (count <= 0)
                    {
                        complete = ok;
                        return ranges;
                    }

                    long next = cursor;
                    for (int i = 0; i < count; i++)
                    {
                        AllocatedSpan span = new AllocatedSpan();
                        span.Offset = Marshal.ReadInt64(output, i * 16);
                        span.Length = Marshal.ReadInt64(output, i * 16 + 8);
                        if (span.Length > 0)
                            ranges.Add(span);
                        long spanEnd = span.Offset + span.Length;
                        if (spanEnd > next)
                            next = spanEnd;
                    }

                    if (ok)
                    {
                        complete = true;
                        return ranges;
                    }

                    if (next <= cursor)
                        return ranges;
                    cursor = next;
                }

                complete = true;
            }
            finally
            {
                Marshal.FreeHGlobal(input);
                Marshal.FreeHGlobal(output);
            }

            return ranges;
        }

        sealed class ZeroTracker
        {
            public long Run;
            public long RunOffset;
            public int PageRuns;
            public long FirstPageOffset = -1;
            public bool Big;
            public long BigOffset;
            public long BigLength;
            public long ContigEnd = -1;
        }

        static void CloseZeroRun(ZeroTracker tracker)
        {
            if (tracker.Run >= 0x8000L)
            {
                if (!tracker.Big)
                {
                    tracker.Big = true;
                    tracker.BigOffset = tracker.RunOffset;
                    tracker.BigLength = tracker.Run;
                }
            }
            else if (tracker.Run >= 0x1000L)
            {
                tracker.PageRuns++;
                if (tracker.FirstPageOffset < 0)
                    tracker.FirstPageOffset = tracker.RunOffset;
            }

            tracker.Run = 0;
        }

        static void FeedZeroBytes(ZeroTracker tracker, byte[] data, int count, long filePos)
        {
            if (count <= 0)
                return;
            if (tracker.ContigEnd >= 0 && filePos != tracker.ContigEnd)
                CloseZeroRun(tracker);

            for (int i = 0; i < count; i++)
            {
                if (data[i] == 0)
                {
                    if (tracker.Run == 0)
                        tracker.RunOffset = filePos + i;
                    tracker.Run++;
                }
                else if (tracker.Run != 0)
                {
                    CloseZeroRun(tracker);
                }
            }

            tracker.ContigEnd = filePos + count;
        }

        static void WalkRawRange(IntPtr handle, long start, long end, ScanResult result, List<Finding> rawZeros, List<Finding> decoys, int cap, ZeroTracker zeros)
        {
            if (end <= start)
                return;

            const int chunkSize = 1 << 20;
            IntPtr chunk = Marshal.AllocHGlobal(chunkSize);
            try
            {
                long pos = start;
                while (pos < end)
                {
                    long remaining = end - pos;
                    int ask = remaining > chunkSize ? chunkSize : (int)remaining;
                    long moved;
                    if (!SetFilePointerEx(handle, pos, out moved, 0))
                        return;

                    uint got;
                    if (!Win32Api.ReadFile(handle, chunk, (uint)ask, out got, IntPtr.Zero) || got == 0)
                        return;

                    byte[] data = new byte[got];
                    Marshal.Copy(chunk, data, 0, (int)got);
                    if (got < 8)
                    {
                        FeedZeroBytes(zeros, data, (int)got, pos);
                        return;
                    }

                    int local = 0;
                    int consumed = 0;
                    while (local + 8 <= data.Length)
                    {
                        RecordFields record = ParseRecord(data, local, data.Length - local);
                        if (!record.Ok)
                            break;

                        long fileOffset = pos + local;
                        if (record.HeaderLen != 0 && record.Usn == 0)
                        {
                            result.RawZeroCount++;
                            if (rawZeros.Count < cap)
                                rawZeros.Add(MakeFinding("0xU6", fileOffset, "", "raw +" + fileOffset.ToString("X")));
                        }
                        else if (record.HeaderLen != 0 && record.Usn != fileOffset)
                        {
                            result.DecoyCount++;
                            if (decoys.Count < cap)
                                decoys.Add(MakeFinding("0xU8", record.Usn, FormatLocalTime(record.Timestamp), "offset 0x" + fileOffset.ToString("X")));
                        }

                        local += (int)record.RecLen;
                        consumed = local;
                    }

                    int take = consumed;
                    if (take == 0)
                    {
                        take = 8;
                        if (ReadUInt32(data, 0) == 0)
                        {
                            int zeroEnd = 0;
                            while (zeroEnd < data.Length && data[zeroEnd] == 0)
                                zeroEnd++;
                            if (zeroEnd > take)
                                take = zeroEnd;
                        }
                    }

                    FeedZeroBytes(zeros, data, take, pos);
                    pos += take;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(chunk);
            }
        }

        static IntPtr OpenBackupFile(string path)
        {
            IntPtr handle = Win32Api.CreateFile(
                path,
                Win32Api.GENERIC_READ,
                Win32Api.FILE_SHARE_READ | Win32Api.FILE_SHARE_WRITE | FileShareDelete,
                IntPtr.Zero,
                Win32Api.OPEN_EXISTING,
                Win32Api.FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                return IntPtr.Zero;
            return handle;
        }

        static RecordFields ParseRecord(byte[] data, int start, int remaining)
        {
            RecordFields record = new RecordFields();
            if (remaining < 8 || start < 0 || start + 8 > data.Length)
                return record;

            record.RecLen = ReadUInt32(data, start);
            record.Major = ReadUInt16(data, start + 4);
            if (record.RecLen < 0x38 || record.RecLen > (uint)remaining || (record.RecLen & 7u) != 0)
                return record;
            if (start + record.RecLen > data.Length)
                return record;

            if (record.Major == 2 && record.RecLen >= 60)
            {
                record.Usn = ReadInt64(data, start + 24);
                record.Timestamp = ReadInt64(data, start + 32);
                record.NameLen = ReadUInt16(data, start + 56);
                record.NameOff = ReadUInt16(data, start + 58);
                record.HeaderLen = 60;
            }
            else if (record.Major == 3 && record.RecLen >= 76)
            {
                record.Usn = ReadInt64(data, start + 40);
                record.Timestamp = ReadInt64(data, start + 48);
                record.NameLen = ReadUInt16(data, start + 72);
                record.NameOff = ReadUInt16(data, start + 74);
                record.HeaderLen = 76;
            }

            record.Ok = true;
            return record;
        }

        static string ExtractSlackResidual(byte[] data, int recordStart, uint nameEnd, uint recordLength)
        {
            if (nameEnd >= recordLength)
                return "";

            StringBuilder current = new StringBuilder();
            string best = "";
            uint offset = (nameEnd + 1u) & ~1u;
            while (offset + 2 <= recordLength)
            {
                int index = recordStart + (int)offset;
                if (index < 0 || index + 2 > data.Length)
                    break;

                ushort value = ReadUInt16(data, index);
                if (IsNameChar(value))
                    current.Append((char)value);
                else
                    best = FlushRun(current, best);
                offset += 2;
            }

            best = FlushRun(current, best);
            if (best.Length > 40)
                best = best.Substring(0, 40);
            return best;
        }

        static string FlushRun(StringBuilder current, string best)
        {
            string text = current.ToString().Trim();
            current.Length = 0;
            bool lengthOk = text.Length >= 4 || (text.Length == 3 && text[0] == '.');
            bool distinct = false;
            for (int i = 1; i < text.Length; i++)
            {
                if (text[i] != text[0])
                {
                    distinct = true;
                    break;
                }
            }

            if (lengthOk && distinct && text.Length > best.Length)
                return text;
            return best;
        }

        static bool IsNameChar(ushort value)
        {
            if (value < 0x20 || value > 0x7E)
                return false;
            char character = (char)value;
            return character != '<' && character != '>' && character != ':' && character != '"'
                && character != '/' && character != '\\' && character != '|' && character != '?' && character != '*';
        }

        static string BuildLine(string code, long usn, string timestamp, string residual)
        {
            const string separator = " \u00b7 ";
            StringBuilder line = new StringBuilder();
            line.Append(code);
            line.Append(separator);
            line.Append("0x");
            line.Append(usn.ToString("X"));
            if (!string.IsNullOrEmpty(timestamp))
            {
                line.Append(separator);
                line.Append(timestamp);
            }
            if (!string.IsNullOrEmpty(residual))
            {
                line.Append(separator);
                line.Append("...");
                line.Append(residual);
            }
            return line.ToString();
        }

        static string FormatLocalTime(long fileTime)
        {
            if (fileTime <= 0)
                return "";
            try
            {
                DateTime local = DateTime.FromFileTime(fileTime);
                if (local.Year < 2000 || local.Year > 2100)
                    return "";
                return local.ToString("yyyy/MM/dd HH:mm:ss");
            }
            catch (ArgumentException)
            {
                return "";
            }
        }

        static ushort ReadUInt16(byte[] data, int offset)
        {
            return (ushort)(data[offset] | (data[offset + 1] << 8));
        }

        static uint ReadUInt32(byte[] data, int offset)
        {
            return (uint)data[offset]
                | ((uint)data[offset + 1] << 8)
                | ((uint)data[offset + 2] << 16)
                | ((uint)data[offset + 3] << 24);
        }

        static ulong ReadUInt64(byte[] data, int offset)
        {
            return (ulong)ReadUInt32(data, offset) | ((ulong)ReadUInt32(data, offset + 4) << 32);
        }

        static long ReadInt64(byte[] data, int offset)
        {
            return (long)ReadUInt64(data, offset);
        }
    }
}
