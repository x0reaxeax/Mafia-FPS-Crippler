/**
 * @file main.c
 * @author x0reaxeax (https://github.com/x0reaxeax), schrehor (https://github.com/schrehor)
 * @brief \
 *  This program serves as a performance degrader for Mafia: The City of Lost Heaven.
 *  Modern machines run the game with high framerate, resulting in some missions
 *  being impossible to complete (for example "Exploding Celeste").
 *  This is not a precise FPS limiter. In fact, the idea behind this is pretty stupid:
 *  Creating multiple threads that perform division in a loop.
 *  The performance degrade seems to be very sudden after a certain amount of threads
 *  are created.
 *  For example, I've tested this on Intel Core i5-12600K and running 15 threads
 *  caused no noticable FPS loss, however, spawning a 16th thread sliced the FPS in half.
 *  The game was running at stable capped 60 FPS and 16th thread resulted in 30-35 FPS.
 *  The amount of threads vary depending on hardware.
 *  The "impossible" missions were completed with no issues when running on 30-35 FPS.
 * 
 *  Compile as x86 executable.
 * 
 * @note Setting thread priority of spawned threads to anything higher than 
 *  `THREAD_PRIORITY_NORMAL` resulted in system hang.
 * 
 * @version 0.1
 * @date 2023-02-03
 *
 * @copyright Copyright (c) 2023
 *
 */

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#define EVAL_ERROR(op)  do {            \
    if (!op) {                          \
        fprintf(stderr,                 \
            "[-] %s() failed - E%d\n",  \
            #op,                        \
            GetLastError());            \
        exitStatus = EXIT_FAILURE;      \
        goto _FINAL;                    \
    }                                   \
} while (0);

HANDLE getMafiaProcess(OUT DWORD *targetProcessId) {
    if (NULL == targetProcessId) {
        fprintf(stderr, "[-] Passed NULL pointer\n");
        return NULL;
    }

    PROCESSENTRY32W procEntry32 = { .dwSize = sizeof(PROCESSENTRY32W) };

    HANDLE hProcess = NULL;
    HANDLE thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (!Process32FirstW(thSnapshot, &procEntry32)) {
        fprintf(stderr, "[-] Process32FirstW() failed - E%d\n", GetLastError());
        return NULL;
    }

    while (Process32NextW(thSnapshot, &procEntry32)) {
        if (EXIT_SUCCESS == wcsncmp(procEntry32.szExeFile, L"Game.exe", ARRAYSIZE("Game.exe"))) {
            printf("[+] Found Mafia process - PID %u\n", procEntry32.th32ProcessID);
            hProcess = OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION,
                FALSE,
                procEntry32.th32ProcessID
            );

            if (NULL == hProcess) {
                fprintf(stderr, "[-] OpenProcess() failed - E%d\n", GetLastError());
            }

            *targetProcessId = procEntry32.th32ProcessID;

            break;
        }
    }

    CloseHandle(thSnapshot);
    return hProcess;

}

DWORD WINAPI performanceCrippler(LPVOID loopFlag) {
    long value = 0;
    while (0 != *(volatile BOOL *) loopFlag) {
        value += 500;
        if (0 != value) {
            value /= 3;
        }
    }
    return EXIT_SUCCESS;
}

/**
 * The program obtains a handle to "Game.exe" (Mafia process),
 * allocates RWX memory inside the process address space,
 * copies the `performanceCrippler()` function into it,
 * alongside the BOOLEAN flag `loopFlag`,
 * which controls the execution of running loops.
 * Afterwards, new threads are created under control of the user.
*/
int main(void) {
    BOOL loopFlag = TRUE;
    DWORD targetProcessId = 0;

    int exitStatus = EXIT_SUCCESS;

    HANDLE hProcess = getMafiaProcess(&targetProcessId);

    if (NULL == hProcess || 0 == targetProcessId) {
        return EXIT_FAILURE;
    }

    int  nOpenedThreads;
    SIZE_T bytesWritten = 0;
    HANDLE threadHandles[512] = { NULL };
    LPVOID targetFuncMemory = VirtualAllocEx(
        hProcess,   /* mafia process */
        NULL,       /* system choice */
        512,        /* 512 bytes should be enough to fit the function + sizeof(BOOL) */
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    printf(
        "[+] Allocated 512 bytes in PID %lu at 0x%p for code execution\n",
        targetProcessId, targetFuncMemory
    );

    EVAL_ERROR(targetFuncMemory);
    LPVOID targetFuncFlagAddr = (LPVOID) ((uintptr_t) targetFuncMemory + (512 - sizeof(BOOL)));

    EVAL_ERROR(
        WriteProcessMemory(
            hProcess,
            (LPVOID) ((uintptr_t) targetFuncMemory + (512 - 4)),
            &loopFlag,
            sizeof(loopFlag),
            &bytesWritten
        )
    );

    /* The hard cap for number of spawned threads is 512. 
     * In reality, good luck getting it above 25.
     * (Yes, I'd rather write a pointless note about this,
     *  instead of just editing the value two lines below.)
    */
    for (nOpenedThreads = 0; nOpenedThreads < 512; nOpenedThreads++) {
        char c = 0;
        printf(
            "[*] Press ENTER to create thread in PID %u or 'x' to exit\n"
            "[*] Current running threads = %d\n",
            targetProcessId, nOpenedThreads
        );
        c = getchar();

        if ('x' == c) {
            break;
        }

        EVAL_ERROR(
            WriteProcessMemory(
                hProcess,
                targetFuncMemory,
                performanceCrippler,
                512 - 4,
                &bytesWritten
            )
        );

        threadHandles[nOpenedThreads] = CreateRemoteThread(
            hProcess,
            NULL,
            0,
            targetFuncMemory,
            targetFuncFlagAddr,
            0,
            NULL
        );

        if (NULL == threadHandles[nOpenedThreads]) {
            fprintf(
                stderr,
                "[-] CreateRemoteThread() failed - E%d\n",
                GetLastError()
            );
        }
    }

    loopFlag = FALSE;
    if (!WriteProcessMemory(hProcess, targetFuncFlagAddr, &loopFlag, sizeof(loopFlag), &bytesWritten)) {
        fprintf(stderr, "[-] WPM() failed - E%d\n", GetLastError());
    }

    for (int i = 0; i < nOpenedThreads; i++) {
        printf("[*] Waiting for thread ID %d to finish work..\n", i);
        WaitForSingleObject(threadHandles[i], INFINITE);
        CloseHandle(threadHandles[i]);
    }

_FINAL:
    if (NULL != targetFuncMemory) {
        printf(
            "[*] Freeing 512 bytes in PID %u at 0x%p..\n",
            targetProcessId,
            targetFuncMemory
        );
        if (!VirtualFreeEx(hProcess, targetFuncMemory, 0, MEM_RELEASE)) {
            fprintf(stderr, "[-] VirtualFreeEx() failed - E%d\n", GetLastError());
        }
    }
    CloseHandle(hProcess);

    return exitStatus;
}