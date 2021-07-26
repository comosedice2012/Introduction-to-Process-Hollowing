# Introduction-to-Process-Hollowing
While earning my Cyber Operations degree from Dakota State University, https://dsu.edu/, I found my reverse engineering and malware analysis classes to be the most interesting and challenging. I decided it would be a fun exercise to try to create my own proof of concept malware using the same techniques that I came across in my studies. This was to be a learning opportunity to become more familiar with Windows APIs, the PE file stucture, and to gain more experience using various tools. I chose process hollowing because I found it to be a very clever way to deliver malicious content, and it would fill all the criteria I wanted to cover in this exercise.

What is process hollowing, exactly? There are many references on-line that describe the process in detail, such as, https://attack.mitre.org/techniques/T1055/012/, so I will give a very general description and then you can follow this post to fill in the blanks. It begins by opening a common process, such as firefox.exe, calc.exe, or svchost.exe, to name a few. A common process is used to avoid drawing attention to itself, as opposed to say, an Excel doc running an executable which is highly suspicious, and to possibly evade anti-virus or other security measures. The executable content of this new process is carved out, and in its place, the malicious code is placed and executed. One of the benefits of this technique is, it is a legitimate process so it can hide in plain sight. The process is also created from it's location in the file system, as opposed to a temp file, which also increases the seeming legitimacy of the process. Also, it all happens in memory, so nothing is written to disk, making it even more difficult to detect. Let’s take a look at an example.

## Note:
Some of the addresses and register values may vary from groupings of screenshots. This is because the program was run several times during the writing of this post, and ASLR will give different values for each instance. This is run on a Windows 10 VM using Visual Studio Code.

## Create Process to Hollow
First we need to create our target process that will be hollowed out. For this example “svchost.exe” will be the target process. Figure 1 shows the libraries used, along with a declaration of `ZwUnmapViewofSection()`, which will be used to hollow the process. Then, in Figure 2, the `main()` function begins by initializing two structures, `STARTUPINFOA()`, and `PROCESS_INFORMATION()`, which are used to help populate the `CreateProcessA()` API, which will be used to start our process. Notice that the process is created in the suspended state, which is essential. Detailed information can be found on MSDN for CreateProcessA. 
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa


