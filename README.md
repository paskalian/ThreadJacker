<p align="center">
<img src="https://github.com/paskalian/ThreadJacker/blob/master/Images/ThreadJacker.svg" alt="Menu"/>
</p>

## Information
**Made for educational purposes only.**<br>

**Don't forget that the hijacked thread can be any thread of the target process (usually main) and doesn't have the must to be running when it was hijacked. For summary even though you hijacked the thread, if it was in a sleep state it won't execute the shellcode until it exits that sleep state and continues running.**

**The return value as you can also see is UINT_PTR which will hold up any given value to it, just cast it to it's actual type if you wanna go along, I didn't wanted to use templates.**

## Compatibility
Compatible with both x64 and x86 processes, you **must** use the **specific** version for a process that is x64 or x86 respectively.

## Usage
```cpp
HandleHijack(TargetProcess, HIJACKTYPE::DIRECT, (UINT_PTR)MessageBoxExW, { 0, L"TEXT", L"CAPTION", 0, 0 }, CALLINGCONVENTION::CC_STDCALL);
```
1. HandleHijack is the handler function that does the prior set-up before actually hijacking the thread.
   - The first param is the target process handle which you can obtain by OpenProcess etc.
   - The second param is what I call the HIJACKTYPE which has 3 modes:
     - DIRECT, meaning that the third parameter is a function address that is already inside the target process, in our example case, MessageBoxExW is already inside the target process, this is of course not limited to WinAPI functions, if you have implemented already your own function somehow inside the target process you can make a call from here to it using this mode.
     - SELF, meaning that the third parameter is a 2 UINT_PTR array which the first UINT_PTR is the function address inside the **current process** and the second UINT_PTR is the size of this function. Can be used if you made your own function to be implemented in the target process and then be executed, but don't want to mess with converting the entire function into byte format. **The usage of this mode can result in problems on Debug mode builds (Because no optimization in place it will put stuff inside to help with debugging for the current process context, but within another, it will straight up crash). I would highly recommend to compile this function in release mode and copy the bytes of it and then use it on BYTE mode.**
     - BYTE, meaning that the third parameter is a std::vector\<BYTE\>* which contains your function in byte format to be implemented inside the target process and then be executed.
   
   - The fourth parameter is a std::vector\<std::any\> basically meaning an array of any kind of type (Not limited to that type, you can literally always use any type you want as you can also see from the example) which is where you will put your arguments to be passed into the function. **For now it doesn't support floating point values, but if you are planning to use it on WinAPI functions, that won't be a huge problem.**
   - The last parameter is the calling convention to be used on this function. **Ignored in x64 architecture.**

2. After setting up the HandleHijack(s) compile the project and run the compiled process with a PID parameter.
```
CompiledProcess.exe 1234
```
