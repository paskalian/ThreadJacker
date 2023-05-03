# ThreadJacker
By using this process you can make any function run with a hijacked thread.

## Information
**Made for educational purposes only.**<br>

**Don't forget that the hijacked thread can be any thread of the target process (usually main) and doesn't have the must to be running when it was hijacked. For summary even though you hijacked the thread, if it was in a sleep state it won't execute the shellcode until it runs.**

## Compatibility
64-bit only **for now**.

## Usage
```cpp
HandleHijack(TargetProcess, HIJACKTYPE::DIRECT, (UINT_PTR)MessageBoxA, { 0, "TEXT", "CAPTION", 0});
```
1. HandleHijack is the handler function that does the prior set-up before actually hijacking the thread.
   - The first param is the target process handle which you can obtain by OpenProcess etc.
   - The second param is what I call the HIJACKTYPE which has 3 modes:
     - DIRECT, meaning that the third parameter is a function that is already inside the target process, in our example case, MessageBoxA is already inside the target process, this is of course not limited to WinAPI functions, if you have implemented already your own function somehow inside the target process you can make a call from here to it using this mode.
     - SELF, meaning that the third parameter is a 2 UINT_PTR array which the first UINT_PTR is the function inside the **current process** and the second UINT_PTR is the size of this function. Can be used if you made your own function to be implemented in the target process and then be executed, but don't want to mess with converting the entire function into byte format. **The usage of this mode can result in problems on Debug mode builds.**
     - BYTE, meaning that the third parameter is a std::vector\<BYTE\>* which contains your function in byte format to be implemented inside the target process and then be executed.
   
   - The last parameter is a std::vector\<std::any\> basically meaning an array of any kind of type which is where you will put your arguments to be passed into the function. **For now it only supports 4 parameters and doesn't support floating point values, but if you are planning to use it on WinAPI that won't be a huge problem.**

2. After setting up the HandleHijack(s) compile the project and run the compiled process with a PID parameter.
```
CompiledProcess.exe 1234
```
