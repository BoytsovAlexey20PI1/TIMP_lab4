#pragma once
#include <vector>
#include <string>
#include <map>
#include <codecvt>
#include <locale>
using namespace std;
class modAlphaCipher
{
private:
wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;
wstring numAlpha = L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";  ///<алфавит по порядку
map <wchar_t,int> alphaNum;   ///<ассоциативный массив "номер по символу"
vector <int> key;          ///<ключ
vector<int> convert(const wstring& ws);///<преобразование строка-вектор
wstring convert(const vector<int>& v);///<преобразование вектор-строка
wstring getValidKey(const wstring & ws);///<проверка правильности ключа
wstring getValidOpenText(const wstring & ws);///<проверка правильносьти открытого текста
wstring getValidCipherText(const wstring & ws);///<проверка правильности зашифрованного текста
public:
modAlphaCipher()=delete;///<запретим конструктор без параметров
modAlphaCipher(const wstring& wskey);  ///<конструктор для установки ключа
wstring encrypt(const wstring& open_text);  ///<зашифрование
wstring decrypt(const wstring& cipher_text);///<расшифрование
};
class cipher_error: public invalid_argument///класс исключение
{
public:
explicit cipher_error (const string& what_arg):
invalid_argument(what_arg) {}
explicit cipher_error (const char* what_arg):
invalid_argument(what_arg) {}
};
