using System;
using System.Threading;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;

namespace De.Thekid.INotify
{

    // List of possible changes
    public enum Change
    {
        CREATE, MODIFY, DELETE, MOVED_FROM, MOVED_TO
    }

    /// Main class
    public class Runner
    {
      
        //creating the object that stores the info
        [Serializable]
        public class fileDescriptor{
            public string FilePath{get; set;}
            public long Length{get;set;}
            public int Strings{get;set;}
        }
        /*
        public string FilePath{get; set;}
        public long Length{get;set;}
        public int Strings{get;set;}
        public Runner(){}
        public Runner(string filePath, long length, int strings){
            FilePath = filePath;
            Length = length;
            Strings = strings;
        }
        */


      /// <summary>
/// Writes the given object instance to a binary file.
/// <para>Object type (and all child types) must be decorated with the [Serializable] attribute.</para>
/// <para>To prevent a variable from being serialized, decorate it with the [NonSerialized] attribute; cannot be applied to properties.</para>
/// </summary>
/// <typeparam name="T">The type of object being written to the XML file.</typeparam>
/// <param name="filePath">The file path to write the object instance to.</param>
/// <param name="objectToWrite">The object instance to write to the XML file.</param>
/// <param name="append">If false the file will be overwritten if it already exists. If true the contents will be appended to the file.</param>
public static void WriteToBinaryFile<T>(string filePath, T objectToWrite, bool append = false)
{
    using (Stream stream = File.Open(filePath, append ? FileMode.Append : FileMode.Create))
    {
        var binaryFormatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
        binaryFormatter.Serialize(stream, objectToWrite);
    }
}

/// <summary>
/// Reads an object instance from a binary file.
/// </summary>
/// <typeparam name="T">The type of object to read from the XML.</typeparam>
/// <param name="filePath">The file path to read the object instance from.</param>
/// <returns>Returns a new instance of the object read from the binary file.</returns>
public static T ReadFromBinaryFile<T>(string filePath)
{
    using (Stream stream = File.Open(filePath, FileMode.Open))
    {
        var binaryFormatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
        return (T)binaryFormatter.Deserialize(stream);
    }
}



        // Mappings
        protected static Dictionary<WatcherChangeTypes, Change> Changes = new Dictionary<WatcherChangeTypes, Change>();

        private List<Thread> _threads = new List<Thread>();
        private bool _stopMonitoring = false;
        private ManualResetEventSlim _stopMonitoringEvent;
        private object _notificationReactionLock = new object();
        private Arguments _args = null;

        static Runner()
        {
            Changes[WatcherChangeTypes.Created]= Change.CREATE;
            Changes[WatcherChangeTypes.Changed]= Change.MODIFY;
            Changes[WatcherChangeTypes.Deleted]= Change.DELETE;
        }

        public Runner(Arguments args)
        {
            _args = args;
        }

        /// Callback for errors in watcher
        protected void OnWatcherError(object source, ErrorEventArgs e)
        {
            Console.Error.WriteLine("*** {0}", e.GetException());
        }

        private void OnWatcherNotification(object sender, FileSystemEventArgs e)
        {
            var w = (FileSystemWatcher)sender;

            HandleNotification((FileSystemWatcher)sender, e, () => Output(Console.Out, _args.Format, w, Changes[e.ChangeType], e.Name));
        }
        
        private void OnRenameNotification(object sender, RenamedEventArgs e)
        {
            var w = (FileSystemWatcher)sender;
            HandleNotification(w, e, () =>
            {
                Output(Console.Out, _args.Format, w, Change.MOVED_FROM, e.OldName);
                Output(Console.Out, _args.Format, w, Change.MOVED_TO, e.Name);
            });
        }
        
        private void HandleNotification(FileSystemWatcher sender, FileSystemEventArgs e, Action outputAction)
        {
            // Lock so we don't output more than one change if we were only supposed to watch for one.
            // And to serialize access to the console
            lock (_notificationReactionLock)
            {
                // if only looking for one change and another thread beat us to it, return
                if (!_args.Monitor && _stopMonitoring)
                {
                    return;
                }
        
                if (null != _args.Exclude && _args.Exclude.IsMatch(e.FullPath))
                {
                    return;
                }
        
                outputAction();
        
                // If only looking for one change, signal to stop
                if (!_args.Monitor)
                {
                    _stopMonitoring = true;
                    _stopMonitoringEvent.Set();
                }
            }
        }

        /// Output method
        protected void Output(TextWriter writer, string[] tokens, FileSystemWatcher source, Change type, string name)
        {
            var path = "";
            foreach (var token in tokens)
            {
                path = Path.Combine(source.Path, name);
                switch (token[0])
                {
                    case 'e':
                        
                        writer.Write(type);
                        if (Directory.Exists(path))
                        {
                            writer.Write(",ISDIR");
                        }
                        break;
                    case 'f': writer.Write(Path.GetFileName(path)); break;
                    case 'w': writer.Write(Path.Combine(source.Path, Path.GetDirectoryName(path))); break;
                    case 'T': writer.Write(DateTime.Now); break;
                    default: writer.Write(token); break;
                }

            }
//ALMELL~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            FileInfo f = new FileInfo(path);
            long s1 = f.Length;

            Process proc = new Process {
                StartInfo = new ProcessStartInfo {
                    FileName = "strings.exe",
                    Arguments = path,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            int count = 0;
            while (!proc.StandardOutput.EndOfStream) {
                string line = proc.StandardOutput.ReadLine();
                // do something with line
                if(count  > 4){
                    //Console.Error.WriteLine(line);
                }
                count++;
            }

            writer.WriteLine();
            Console.Error.WriteLine("Length : " + s1);
            Console.Error.WriteLine("Number of Strings : " + (count - 4));
            


/*
            Console.Error.WriteLine("HI. we at least made it here.");
            fileDescriptor fd = new fileDescriptor(){FilePath = path, Length = s1, Strings = count};
            bool fileInHere = false;
            WriteToBinaryFile("info/store.xml", fd, true);

            if(new FileInfo( "info/store.xml" ).Length == 0 )
            {
              // do nothing
              Console.Error.WriteLine("hi so here we are");
            }else{
            using (Stream stream = File.Open("info/store.xml", FileMode.Open))
            {

                var binaryFormatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                stream.Position = 0;
                List<fileDescriptor> list = new List<fileDescriptor>();
                while(stream.Position<stream.Length)
                {
                     //deserialize each object
                     fileDescriptor deserialized = (fileDescriptor)binaryFormatter.Deserialize(stream);
                     //add individual object to a list
                     list.Add(deserialized);
//                     Console.Error.WriteLine(deserialized.FilePath);
                    fileDescriptor fdOld = (fileDescriptor)binaryFormatter.Deserialize(stream);
                    Console.Error.WriteLine(fdOld.FilePath);
                    Console.Error.WriteLine(fd.FilePath);

                    if(object.Equals(fdOld.FilePath, fd.FilePath)){
                        Console.Error.WriteLine("WE GOT IN HERE");
                        fileInHere = true;
                        Console.Error.WriteLine(fdOld.FilePath);
                        if((fdOld.Length == 0) | (fd.Length == 0)){
                            //just skip it
                        }else{
                        long oldRatio = fdOld.Strings/fdOld.Length;
                        long newRatio = fd.Strings/fd.Length;
                        if(fd.Length > 6000000){
                            Console.Error.WriteLine("WE GOT IN HERE2");

                            //probably encrypted, check it
                            if(newRatio < .035){
                                Console.Error.WriteLine("WE GOT IN HERE3");

                                if(oldRatio > newRatio){
                                    Console.Error.WriteLine("YO WE HAVE ENCRYPTION HERE");
                                }
                            }

                        }
                    }
                }



                }


*/


                /*
                var binaryFormatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                fileDescriptor fdOld = (fileDescriptor)binaryFormatter.Deserialize(stream);
                Console.Error.WriteLine(fdOld.FilePath);
                Console.Error.WriteLine(fd.FilePath);

                if(object.Equals(fdOld.FilePath, fd.FilePath)){
                    Console.Error.WriteLine("WE GOT IN HERE");
                    fileInHere = true;
                    Console.Error.WriteLine(fdOld.FilePath);
                    long oldRatio = fdOld.Strings/fdOld.Length;
                    long newRatio = fd.Strings/fd.Length;
                    if(fd.Length > 6000000){
                        Console.Error.WriteLine("WE GOT IN HERE2");

                        //probably encrypted, check it
                        if(newRatio < .035){
                            Console.Error.WriteLine("WE GOT IN HERE3");

                            if(oldRatio > newRatio){
                                Console.Error.WriteLine("YO WE HAVE ENCRYPTION HERE");
                            }
                        }
                    }
                }

            }
        }
                        */
        /*
            if(fileInHere == false){
                WriteToBinaryFile("info/store.xml", fd, true);
            }
            */
        }

        public void Processor(object data)
        {
            string path = (string)data;

            using (var w = new FileSystemWatcher {
                Path = path,
                IncludeSubdirectories = _args.Recursive,
                Filter = "*.*"
            }) {
                w.Error += new ErrorEventHandler(OnWatcherError);

                // Parse "events" argument
                WatcherChangeTypes changes = 0;
                if (_args.Events.Contains("create"))
                {
                    changes |= WatcherChangeTypes.Created;
                    w.Created += new FileSystemEventHandler(OnWatcherNotification);
                }
                if (_args.Events.Contains("modify"))
                {
                    changes |= WatcherChangeTypes.Changed;
                    w.Changed += new FileSystemEventHandler(OnWatcherNotification);
                }
                if (_args.Events.Contains("delete"))
                {
                    changes |= WatcherChangeTypes.Deleted;
                    w.Deleted += new FileSystemEventHandler(OnWatcherNotification);
                }
                if (_args.Events.Contains("move"))
                {
                    changes |= WatcherChangeTypes.Renamed;
                    w.Renamed += new RenamedEventHandler(OnRenameNotification);
                }

                // Main loop
                if (!_args.Quiet)
                {
                    Console.Error.WriteLine(
                        "===> {0} for {1} in {2}{3} for {4}",
                        _args.Monitor ? "Monitoring" : "Watching",
                        changes,
                        path,
                        _args.Recursive ? " -r" : "",
                        String.Join(", ", _args.Events.ToArray())
                    );
                }
                w.EnableRaisingEvents = true;
                _stopMonitoringEvent.Wait();
            }
        }

        public void StdInOpen()
        {
            while (Console.ReadLine() != null);
            _stopMonitoring = true;
            _stopMonitoringEvent.Set();
        }

        /// Entry point
        public int Run()
        {
            using (_stopMonitoringEvent = new ManualResetEventSlim(initialState: false))
            {
                foreach (var path in _args.Paths)
                {
                    var t = new Thread(new ParameterizedThreadStart(Processor));
                    t.Start(path);
                    _threads.Add(t);
                }

                var s = new Thread(new ThreadStart(StdInOpen));
                s.Start();
                _threads.Add(s);
                _stopMonitoringEvent.Wait();

                foreach (var thread in _threads)
                {
                    if (thread.IsAlive) thread.Abort();
                    thread.Join();
                }
                return 0;
            }
        }

        /// Entry point method
        public static int Main(string[] args)
        {
            var p = new ArgumentParser();

            // Show usage if no args or standard "help" args are given
            if (0 == args.Length || args[0].Equals("-?") || args[0].Equals("--help"))
            {
                p.PrintUsage("inotifywait", Console.Error);
                return 1;
            }

            // Run!
            return new Runner(p.Parse(args)).Run();
        }
    }
}
