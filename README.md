# Introduction-to-Process-Hollowing
While earning my Cyber Operations degree from Dakota State University, https://dsu.edu/, I found my reverse engineering and malware analysis classes to be the most interesting and challenging. I decided it would be a fun exercise to try to create my own proof of concept malware using the same techniques that I came across in my studies. This was to be a learning opportunity to become more familiar with Windows APIs, the PE file stucture, and to gain more experience using various tools. I chose process hollowing because I found it to be a very clever way to deliver malicious content, and it would fill all the criteria I wanted to cover in this exercise. Let's begin.

What is process hollowing, exactly? There are many references on-line that describe the process in detail, such as, https://attack.mitre.org/techniques/T1055/012/, so I will give a very general description and then you can follow this post to fill in the blanks. It begins by opening a common process, such as firefox.exe, calc.exe, or svchost.exe, to name a few. A common process is used to avoid drawing attention to itself, as opposed to say, an Excel doc running an executable which is highly suspicious, and to possibly evade anti-virus or other security measures. The executable content of this new process is carved out, and in its place, the malicious code is placed and executed. One of the benefits of this technique is, it is a legitimate process so it can hide in plain sight. The process is also created from it's location in the file system, as opposed to a temp file, which also increases the seeming legitimacy of the process. Also, it all happens in memory, so nothing is written to disk, making it even more difficult to detect. Let’s take a look at an example.

## Note:
Some of the addresses and register values may vary from groupings of screenshots. This is because the program was run several times during the writing of this post, and ASLR will give different values for each instance. This is run on a Windows 10 VM using Visual Studio Code.

## Create Process to Hollow
First we need to create our target process that will be hollowed out. For this example “svchost.exe” will be the target process. Figure 1 shows the libraries used, along with a declaration of `ZwUnmapViewofSection()`, which will be used to hollow the process. Then, in Figure 2, the `main()` function begins by initializing two structures, `STARTUPINFOA()`, and `PROCESS_INFORMATION()`, which are used to help populate the `CreateProcessA()` API, which will be used to start our process. Notice that the process is created in the suspended state, which is essential. Detailed information can be found on MSDN for [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa). 


![cLibraries](https://user-images.githubusercontent.com/69214982/127059867-9c5d0529-7faa-45a9-981a-daae8f1626c7.png)

[Fig. 1]

![main](https://user-images.githubusercontent.com/69214982/127059892-0a65c336-c27c-45cb-97fa-95949ca367fc.png)

[Fig. 2]

We can set a break-point in a debugger, just after the CreateProcessA function, and look in ProcessHacker to verify that our code launches an svchost.exe process.

![IdaSvchostSpawn](https://user-images.githubusercontent.com/69214982/127059883-f5aef305-adef-4c78-8b67-e814b0b8c847.png)

## Open Malicious Executable

Now that we can spawn a target process, we need to open the malicious process. We can use [`CreateFileA()`](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) to get a handle to the location of our malicious file in the file system, as shown in Fig. 3.

![createFileAHandle](https://user-images.githubusercontent.com/69214982/127059870-0acf3b78-30ad-4013-980e-648c92438d83.png)

[Fig. 3]


Now that we know where the file is, we can use [`VirtualAlloc()`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) to allocate memory for that file. One of the parameters for VirtualAlloc is `dwSize`, so, first we need to run `GetFileSize()` to get the size of the malicious file, and then we can allocate memory, as shown in Fig. 4. Make sure you give Read/Write permission for the `flProtect` member. VirtualAlloc will now return the base address to the newly allocated memory.

![virtualAllocMalFile](https://user-images.githubusercontent.com/69214982/127059919-2bc42080-4ebb-450d-b5ef-ce03bf85bab3.png)

[fig. 4]

Now we can use `ReadFile()` to read our malicious content using the handle we got from CreateFileA, and write it into our new memory allocation using the pointer we got from VirtualAlloc, then close the source handle, as shown in Fig. 5. Notice you need to declare the variable ReadFile uses to store the number of bytes the operation reads.

![readFile](https://user-images.githubusercontent.com/69214982/127059906-4b7d6be6-6a34-46b1-bc70-e7f50770e15a.png)

[Fig. 5]

Now let’s check to make sure everything is working correctly. Using a debugger we can inspect the memory that has been allocated by `VirtualAlloc()`. It’s return value, in register `EAX`, will be the base address of the allocation. In Fig. 6 we can see `EAX (RAX)`, contains `0x3C0000`. Fig. 7 shows this memory location is empty immediately following our call to `VirtualAlloc()`.

![virtualAllocAddress](https://user-images.githubusercontent.com/69214982/127059917-5e539212-c1d0-44ec-8543-4b82a2dfaaef.png)

[Fig. 6]

![memoryBeforeReadFile](https://user-images.githubusercontent.com/69214982/127059900-b7b02fec-6773-4ec0-9d64-3865d1b043b5.png)

[Fig. 7]

Next, we can look at the same memory location after the call to ReadFile(), which should have read our PE file into the specified memory. Figure 8 shows the memory is now populated with data which appears to be a PE file, indicated by the magic number (MZ).

![memoryPostReadFile](https://user-images.githubusercontent.com/69214982/127059901-1f766b0e-cf5c-4209-84d8-93b60fa05828.png)

[Fig. 8]

## Process Hollowing

In order to hollow our process we will need to know the base address of our victim process. This is the location in memory where our process begins. We will also need the entry point. This is location where our processes executable code is located. This will need to be changed to reflect the address of our malicious code, so it will be executed when the process runs. Both of these pieces of information can be found from our victim process’ thread context. This can be found by using the [`GetThreadContext()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext) API. This API will populate a context structure, that includes registers storing the values we are looking for. Detailed information on the structure can be found [here](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext).

We are looking for the values in register `EAX` (entry point memory location), and `EBX`(PEB memory location, which can be used to find the base address). We can find these values using Windbg. The “~” command shows available threads. The primary thread is “0” which is in the “Suspend” state, as shown in Fig. 9.

![ThreadsAvailable](https://user-images.githubusercontent.com/69214982/127059915-d0c7777f-1d54-4028-8313-323c732cf4e2.png)

[Fig. 9]

Use the “~0s” command to switch to the primary process thread, then we can examine the PEB contents. We can see that the `ImageBaseAddress` is `0x970000` in Fig, 10.

![pebImageBase](https://user-images.githubusercontent.com/69214982/127059903-d00f9208-8555-45e7-b2b5-10aa15a115a9.png)

[Fig. 10]

If we look at register `EBX` in Fig. 11, we see the address `0x30d7000`. This is the address of the PEB. If we look at the contents of that address + `0x8` (offset from Fig. 10), we can see that the base address `0x00f40000` is indeed at this location.

![threadRegisters](https://user-images.githubusercontent.com/69214982/127059911-5afa4ed7-52b0-4dd9-87f5-684e36fd3ec1.png)

[Fig. 11]

Next we need to get the target process’ thread context, in order to get the register value with its base address. Using `GetThreadContext()` will give us a pointer to a context structure which contains the register values that are needed (See Fig. 12). With our context structure pointer (‘c’), we can get the address of the PEB from register `EBX`. Adding `0x8` will give us the address that contains the image base address of our target process, as was demonstrated in Fig. 10.

![threadCtxtBaseImageAddy](https://user-images.githubusercontent.com/69214982/127059910-2737caba-ec19-4509-92ee-b742b83a6cd8.png)

[Fig. 12]

Now we are armed with all the information we need, therefore, we can begin the actual process of hollowing out the executable. First, we get a handle to ntdll.dll which we then use to get the address of `ZwUnmapViewOfFile()`. This function will free the memory in our target process which will allow us to write the malicious file in its place. The code snippet in Fig. 13 shows this process.

![hollowProcess](https://user-images.githubusercontent.com/69214982/127059876-e3ae1d6c-2b05-44e8-a83d-56e3d4998c66.png)

[Fig. 13]

Let’s look at the memory to verify what is happening here. We can set a breakpoint before the call to unMapViewOfSection as shown in Fig. 14. Our output shows a PID of 1604, and a base address of `0x00580000`. If we look at that memory address we can see the DOS Header. Then, immediately after the call, the memory has been zeroed out, indicating a successful hollowing. (Fig. 15)

![HdXPreHollow](https://user-images.githubusercontent.com/69214982/127059875-8bfc30ee-a652-4bd3-b34a-e9da2eb392db.png)

[Fig. 14]

![HxDPost](https://user-images.githubusercontent.com/69214982/127059878-4c5386de-d6fc-4abb-a172-8d000415ae71.png)

[Fig. 15]

## Allocate Memory In Hollowed Process

In order to write our malicious file into the hollowed process, we will need to use virtualAlloc to make the memory writable and to tell the OS how much space we will need to reserve. In order to use virtualAlloc we need to know the size of the image. This is different than the size of the *file* we used earlier. When the process is running it typically will not be the same size as the stored file. This can be caused by several factors, one of which is the compression of sections. We can access this information from the file headers. Figure 16 shows the layout of the DOS Header, PE Header, and Optional Header, respectively(Images courtesy of corkami.com). The DOS Header contains `e_lfanew` which is the number of bytes it takes to get from the DOS Header to the PE Header. From there, we can get to the Optional Header, which contains `SizeOfImage`. The code in Fig. 17 shows how this works.

![PEHeadersDiagram](https://user-images.githubusercontent.com/69214982/127059905-8b3e9d29-7f5b-4ff8-8fc4-49ba11b5b7dc.png)

[Fig. 16]

![optHeaderSizeOfImage](https://user-images.githubusercontent.com/69214982/127059902-db244a6f-f9ea-4073-8aed-32910897cffa.png)

[Fig. 17]

Now we can use `VirtualAllocEx()` like before, however, this time we need to make sure we assign read/write/execute permissions to this memory. (Fig. 18)

![virtualAllocEx](https://user-images.githubusercontent.com/69214982/127059918-b6e63d6f-4fea-489f-a3c1-9f344d93011a.png)

[Fig. 18]

## Write Malicious File Into Target

Now it’s finally time to write the malicious file into memory. Figure 19 is a diagram of the PE file structure. As you can see, we first need to write the headers, then we can write the sections, which contain all of the executable data. 

![PEFileStructure](https://user-images.githubusercontent.com/69214982/127059904-549bd5fd-3fd0-4185-a40c-b482c9b689e5.png)

[Fig. 19]

We use `WriteProcessMemory()` to write the headers to memory. Figure 21 shows the `IMAGE_NT_HEADER` structure, which contains the OptionalHeader. Figure 22 shows the `IMAGE_OPTIONAL_HEADER` structure which contains the `SizeOfHeaders`  value we need for WriteProcessMemory.

![writeHeaders](https://user-images.githubusercontent.com/69214982/127059923-5f5c4edf-4951-4a97-973c-0230626aa3bd.png)

[Fig. 20]

![ImageNtHeader](https://user-images.githubusercontent.com/69214982/127059886-4e3f13e9-fda6-4309-9d03-2963c0bb570b.png)

[Fig. 21]

![ImageOptHeader](https://user-images.githubusercontent.com/69214982/127059889-eb5e7d4c-8b63-450a-a4f8-3f12bde8e3c1.png)

[Fig. 22]

Writing the sections is a little bit tricky. We can use a loop to copy each section. In order to do this, we need the `NumberOfSections`, which is located in the `IMAGE_FILE_HEADER` structure (Fig. 24), which is in the NT Headers. Now we need to find the first Section Header. If we add `e_lfanew` and the size of the headers to the base address, we will be in the first Section Header . Then we use `WriteProcessMemory()` again, getting our to and from addresses from the `IMAGE_SECTION_HEADER` structure (See Fig. 25 for details). Now we can loop through and write all of the sections by adding the size of each `IMAGE_SECTION_HEADER`. Figure 23 shows the corresponding code.

![WriteSectionsToMem](https://user-images.githubusercontent.com/69214982/127059925-32d1a9ce-0fb3-4117-b8e8-57daa4b5d482.png)
[Fig. 23]

![imageFileHeader](https://user-images.githubusercontent.com/69214982/127059884-1c6816c1-0dca-4c91-910c-1002df93a774.png)

[Fig. 24]

![imageSectionHeader](https://user-images.githubusercontent.com/69214982/127059890-1fbdf09d-3590-4bd5-a85a-f96c888c03d5.png)

[Fig. 25]

Once the loop is complete, the injection of our malicious code should be complete. Again, we can try to verify this by looking at the memory of our suspended process after the loop completes. In Fig. 26 we can see that once again we have a PE file instead of the zeroed out memory we had after unmapping the process. This is what we are hoping to see. 

![HxDPostSections](https://user-images.githubusercontent.com/69214982/127059879-c8f0a808-ccfd-4a96-8cff-bd4bad24ab22.png)

[Fig. 26]

All that is left to do is change the EAX value in the thread context to reflect the entry point of our newly injected process, which we can also get from the headers, and resume the thread (Fig. 27)

![resumeThread](https://user-images.githubusercontent.com/69214982/127059909-c5f29b0b-5889-41ad-bd7a-1cf3d02c3c06.png)

[Fig. 27]

The final proof is to run the program in its entirety, and see what happens. As you can see in Fig. 28 the command line output tells our process has a PID of 2980. If we look in ProcessHacker we can see that our program did spawn an svchost.exe with a matching PID. However, what has been opened is our “malicious” program which is just a dialog box telling us it is malware. We have been successful in our endeavors!
This is a very simple example of how process hollowing works. There are many different ways to accomplish this, but this is the method that worked for me. There was a lot of trial and error, but I did learn a lot on the way, which was really what this was all about. Of course, being successful in the end was also very rewarding! I hope this helps to understand how this process works. Happy hacking.

![hollowSuccessful](https://user-images.githubusercontent.com/69214982/127059877-23ca0a61-c6c4-4b89-859f-0df07a3e7b99.png)

[Fig. 28]

## Post Note:
It has been brought to my attention that I didn't show how to perform Image Base Relocation, via the .reloc section. I have seen examples of process hollowing using this and some that don't. I tested my code with my "malicious" pop-up as well as with calc.exe and iexplore.exe. Having had positive results with these I didn't proceed with rebasing. I may revisit this at a later time and see if I can successfully rebase the image to get a more complete resolution. For now, I am pretty satisfied with my small success!

