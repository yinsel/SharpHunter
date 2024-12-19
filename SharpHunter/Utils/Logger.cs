using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Web.Script.Serialization;

namespace SharpHunter.Utils
{
    public static class Logger
    {
        static string dateTime = DateTime.Now.ToString("yyyy-M-dd_HH-mm-ss");
        private static string fileName;
        private static bool _isLogEnabled = false;
        private static bool _isZipEnabled = false;
        private static string _logDirectory = "HunterLogs";
        public static string globalLogDirectory = Path.Combine(Path.GetTempPath(), _logDirectory);
        private static string logFilePath;

        public static void Initialize(bool isLog, bool isZip, string commandName)
        {
            _isLogEnabled = isLog;
            _isZipEnabled = isZip;
            string _commandName = commandName.Replace("Command", "");
            fileName = $"{_commandName}_{dateTime}.log";

            logFilePath = Path.Combine(Path.GetTempPath(), fileName);
            if (_isZipEnabled)
            {
                _isLogEnabled = true;
                _logDirectory = Path.Combine(Path.GetTempPath(), _logDirectory);
                Directory.CreateDirectory(_logDirectory);
                logFilePath = Path.Combine(_logDirectory, fileName);
            }
        }

        public static void SetLogToFile()
        {
            if (_isZipEnabled)
            {
                try
                {
                    string zipFilePath = Path.Combine(Directory.GetCurrentDirectory(), $"{_logDirectory}.zip");
                    if (File.Exists(zipFilePath))
                    {
                        File.Delete(zipFilePath); 
                    }
                    using (var zip = ZipStorer.Create(zipFilePath, "SharpHunter Hunting Log Files"))
                    {
                        AddFilesToZip(_logDirectory, zip, _logDirectory);
                    }
                    Directory.Delete(_logDirectory, true);
                    Console.WriteLine($"[+] Compressed: {zipFilePath}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Failed to create zip: {ex.Message}");
                }
            }
        }

        private static void AddFilesToZip(string dirPath, ZipStorer zip, string baseDirPath)
        {
            foreach (string file in Directory.GetFiles(dirPath))
            {
                string relativePath = file.Substring(baseDirPath.Length + 1);
                zip.AddFile(ZipStorer.Compression.Deflate, file, relativePath, "");
            }

            foreach (string subDir in Directory.GetDirectories(dirPath))
            {
                AddFilesToZip(subDir, zip, baseDirPath);
            }
        }

        public static void WriteLine(string line)
        {
            Console.WriteLine(line);
            if (_isLogEnabled)
            {
                WriteToFile(line + Environment.NewLine);
            }
        }

        public static void Write(string message, bool error = false)
        {
            if (error)
            {
                Console.ForegroundColor = ConsoleColor.Red;
            }

            Console.Write(message);

            if (error)
            {
                Console.ResetColor();
            }

            if (_isLogEnabled)
            {
                WriteToFile(message);
            }
        }

        private static void WriteToFile(string content)
        {
            try
            {
                using (StreamWriter sw = new StreamWriter(logFilePath, true, Encoding.UTF8)) // Write with UTF-8 encoding
                {
                    sw.Write(content);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed to write to log file: {ex.Message}");
            }
        }

        public static void WriteLine(string format, params object[] args)
        {
            WriteLine(string.Format(format, args));
        }

        public static string LogFilePath => logFilePath;

        public static void PrintTable(List<string> header, List<List<string>> items)
        {
            List<int> colLen = header.Select((t, i) => Math.Max(items.Any() ? items.Select(row => GetDisplayLength(row[i])).Max() : 0, GetDisplayLength(t))).ToList();

            PrintRow(header, colLen);
            PrintSeparator(colLen);

            foreach (var row in items)
            {
                PrintRow(row, colLen);
            }
        }

        static void PrintRow(List<string> row, List<int> colLen)
        {
            string rowText = string.Join("  ", row.Select((t, i) => PadRight(t, colLen[i])).ToArray());
            WriteLine(rowText);
        }

        static void PrintSeparator(List<int> colLen)
        {
            string separator = string.Join("  ", colLen.Select(len => new string('-', len)).ToArray());
            WriteLine(separator);
        }

        static int GetDisplayLength(string text)
        {
            return text.Sum(c => c > 127 ? 2 : 1); // 中文字符宽度为2，其他为1
        }

        static string PadRight(string text, int totalWidth)
        {
            int padding = totalWidth - GetDisplayLength(text);
            return text + new string(' ', padding);
        }
        public static void TaskHeader(string taskName, int level)
        {
            int totalWidth = 55;
            int symbolsCount = Math.Max((totalWidth - taskName.Length - 2) / 2, 0);

            string leftSymbols, rightSymbols, paddingSymbol;
            if (level == 1)
            {
                leftSymbols = new string('>', symbolsCount);
                rightSymbols = new string('<', symbolsCount);
                paddingSymbol = "<";
            }
            else
            {
                leftSymbols = rightSymbols = new string('=', symbolsCount);
                paddingSymbol = "=";
            }

            string header = $"{leftSymbols} {taskName} {rightSymbols}";

            while (header.Length < totalWidth)
            {
                header += paddingSymbol;
            }

            WriteLine("\n" + header + "\n");
        }

        public static void WriteStructsToJson<T>(List<T> structs, string directoryPath, string fileName)
        {
            Directory.CreateDirectory(directoryPath);
            string jsonFilePath = Path.Combine(directoryPath, fileName.Replace(" ", "-"));

            try
            {
                var dictList = structs.Select(ToDictionaryWithLowercaseKeys).ToList();

                JavaScriptSerializer serializer = new JavaScriptSerializer();
                string jsonString = serializer.Serialize(dictList);
                File.WriteAllText(jsonFilePath, jsonString, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                WriteLine($"[-] Failed to write to JSON: {ex.Message}");
            }
        }

        private static Dictionary<string, object> ToDictionaryWithLowercaseKeys<T>(T obj)
        {
            Dictionary<string, object> dict = new Dictionary<string, object>();
            var fields = typeof(T).GetFields(BindingFlags.Public | BindingFlags.Instance);
            foreach (var field in fields)
            {
                string key = char.ToLower(field.Name[0]) + field.Name.Substring(1);
                object value = field.GetValue(obj);
                if (value is DateTime dt)
                {
                    value = dt.ToString("yyyy-MM-dd HH:mm:ss");
                }
                dict[key] = value;
            }
            return dict;
        }

        public static void WriteStructsToCsv<T>(List<T> structs, string directoryPath, string fileName)
        {
            Directory.CreateDirectory(directoryPath);
            string csvFilePath = Path.Combine(directoryPath, fileName.Replace(" ", "-"));

            try
            {
                using (StreamWriter sw = new StreamWriter(csvFilePath, false, Encoding.UTF8))
                {
                    var fields = typeof(T).GetFields(BindingFlags.Public | BindingFlags.Instance);

                    sw.WriteLine(string.Join(",", fields.Select(f => f.Name).ToArray()));

                    foreach (var item in structs)
                    {
                        var values = fields.Select(f => f.GetValue(item)?.ToString() ?? string.Empty).Select(v => $"\"{v}\"").ToArray();
                        sw.WriteLine(string.Join(",", values));
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLine($"[-] Failed to write to CSV: {ex.Message}");
            }
        }

        public static void PrintKeyValuePairsFromStructs<T>(List<T> structs)
        {
            foreach (var item in structs)
            {
                var fields = typeof(T).GetFields(BindingFlags.Public | BindingFlags.Instance);
                foreach (var field in fields)
                {
                    string name = field.Name;
                    string value = field.GetValue(item)?.ToString() ?? string.Empty;
                    WriteLine($"  {name}: {value}");
                }
                WriteLine(""); 
            }
        }

        public static void PrintTableFromStructs<T>(List<T> structs)
        {
            if (structs.Count == 0)
            {
                WriteLine("[-] No data to display.");
                return;
            }

            var fields = typeof(T).GetFields(BindingFlags.Public | BindingFlags.Instance);
            List<string> headers = fields.Select(f => f.Name).ToList();
            List<List<string>> items = structs.Select(item => fields.Select(f => f.GetValue(item)?.ToString() ?? string.Empty).ToList()).ToList();

            PrintTable(headers, items);
        }
    }
}