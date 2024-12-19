using System.IO;
using System.Collections.Generic;
using System.Drawing.Imaging;
using System.Drawing;
using System;
using System.Windows.Forms;
using SharpHunter.Utils;

namespace SharpHunter.Commands
{
    class ScreenShotPostCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Attack Mode", 1);
            Logger.WriteLine("[*] Capture a full-screen screenshot of all displays.");

            string savePath = null;
            if (args.Count > 0)
            {
                // 处理带空格的路径
                savePath = string.Join(" ", args.ToArray()).Trim('"'); // 将 List<string> 转换为 string[] 后再进行 Join
            }

            CaptureScreenshot(savePath);
        }

        public static Bitmap CaptureScreenshot(string savePath = null)
        {
            // 在截图前设置DPI感知
            Win32.SetupDpiAwareness();
 
            // 获取所有屏幕的总宽度和总高度
            int totalWidth = 0;
            int totalHeight = 0;
            int minX = 0;
            int minY = 0;

            // 确保至少有一个屏幕
            if (Screen.AllScreens.Length == 0)
            {
                throw new InvalidOperationException("No screens found to capture.");
            }

            foreach (Screen screen in Screen.AllScreens)
            {
                totalWidth = Math.Max(totalWidth, screen.Bounds.X + screen.Bounds.Width);
                totalHeight = Math.Max(totalHeight, screen.Bounds.Y + screen.Bounds.Height);
                minX = Math.Min(minX, screen.Bounds.X);
                minY = Math.Min(minY, screen.Bounds.Y);
            }

            totalWidth -= minX;
            totalHeight -= minY;

            // 创建位图
            using (Bitmap screenshot = new Bitmap(totalWidth, totalHeight, PixelFormat.Format32bppArgb))
            {
                using (Graphics screenGraph = Graphics.FromImage(screenshot))
                {
                    screenGraph.Clear(Color.Black);

                    // 设置高质量绘图
                    screenGraph.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                    screenGraph.CompositingQuality = System.Drawing.Drawing2D.CompositingQuality.HighQuality;
                    screenGraph.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.HighQuality;
                    screenGraph.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;

                    // 对每个屏幕分别进行截图
                    foreach (Screen screen in Screen.AllScreens)
                    {
                        Rectangle bounds = screen.Bounds;
                        try
                        {
                            screenGraph.CopyFromScreen(
                                bounds.X, bounds.Y,
                                bounds.X - minX, bounds.Y - minY,
                                bounds.Size,
                                CopyPixelOperation.SourceCopy);
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error while capturing screen {bounds}: {ex.Message}");
                            return null;
                        }
                    }
                }

                string fileName = Environment.MachineName + "@" + Environment.UserName + "_" + DateTime.Now.ToString("yyyy-M-dd_HH-mm-ss") + ".png";
                string fullFilePath;

                if (string.IsNullOrEmpty(savePath))
                {
                    string picturesPath = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
                    fullFilePath = Path.Combine(picturesPath, fileName);
                }
                else
                {
                    if (!Directory.Exists(savePath))
                    {
                        throw new DirectoryNotFoundException($"The directory {savePath} does not exist.");
                    }
                    fullFilePath = Path.Combine(savePath, fileName);
                }

                try
                {
                    screenshot.Save(fullFilePath, ImageFormat.Png);
                    Logger.WriteLine("[+] Screenshot saved to " + fullFilePath);
                }
                catch (Exception ex)
                {
                    throw new IOException($"Error saving screenshot to {fullFilePath}. {ex.Message}", ex);
                }

                return screenshot;
            }
        }
    }
}
