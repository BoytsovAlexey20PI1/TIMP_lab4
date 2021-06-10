#include <iostream>
#include "modAlphaCipher.h"
#include <codecvt>
using namespace std;
char askEncodeDecode (string question)
{
    wchar_t response;
    do {
        cout<<question<<"(c/d/e):";
        wcin>>response;
    } while(response!='c' && response!='d' && response!='e');
    return response;
}
int main ()
{
    char g;
    locale loc("ru_RU.UTF-8");
    locale::global(loc);
    wstring wstr,wstr_kl;
    do {
        g = askEncodeDecode("Кодирование, декодирование или выход?");
        if (g == 'c') {
            cout << "Введите строку: ";
            wcin.get();
            getline(wcin,wstr);
            cout << "Введите ключ: ";
            getline(wcin,wstr_kl);
            try {
                modAlphaCipher cipher(wstr_kl);
                wstring cipherText = cipher.encrypt(wstr);
                wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
                cout<<codec.to_bytes(cipherText)<<endl;
            } catch (cipher_error & e) {

                cout <<  e.what() << endl;

            }
        }
        if (g == 'd') {
            cout << "Введите строку: ";
            wcin.get();getline(wcin,wstr);
            cout << "Введите ключ: "; getline(wcin,wstr_kl);
            try {
                modAlphaCipher cipher(wstr_kl);
                wstring OpenText = cipher.decrypt(wstr);
                wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
                cout<<codec.to_bytes(OpenText)<<endl;
            } catch (cipher_error & e) {

                cout <<e.what() << endl;
            }
        }
    } while (g != 'e');
    return 0;

}