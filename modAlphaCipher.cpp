#include <modAlphaCipher.h>
/**
 * @brief Конструктор, принимающий на вход ключ
 * @param ws_key
 * @return Ничего не возвращает
 */
modAlphaCipher::modAlphaCipher(const wstring& wskey)
{
    for (unsigned i=0; i<numAlpha.size(); i++) {
        alphaNum[numAlpha[i]]=i;
    }
    key = convert(getValidKey(wskey));
}
/**
 * @brief Метод encrypt зашифровывает текст.
 * @param open_text
 * @return Зашифрованный текст
 */
wstring modAlphaCipher::encrypt(const wstring& open_text)
{
    vector<int> work = convert(getValidOpenText(open_text));
    for(unsigned i=0; i < work.size(); i++) {
        work[i] = (work[i] + key[i % key.size()]) % alphaNum.size();
    }
    return convert(work);
}
/**
 * @brief Метод encrypt дешифрованный текст.
 * @param cipher_text
 * @return Дешифрованный текст
 */
wstring modAlphaCipher::decrypt(const wstring& cipher_text)
{
    vector<int> work = convert(getValidCipherText(cipher_text));
    for(unsigned i=0; i < work.size(); i++) {
        work[i] = (work[i] + alphaNum.size() - key[i % key.size()]) % alphaNum.size();
    }
    return convert(work);
}
inline vector<int> modAlphaCipher::convert(const wstring& ws)
{
    vector<int> result;
    for(auto c:ws) {
        result.push_back(alphaNum[c]);
    }
    return result;
}
inline wstring modAlphaCipher::convert(const vector<int>& v)
{
    wstring result;
    for(auto i:v) {
        result.push_back(numAlpha[i]);
    }
    return result;
}
/**
 * @brief Данный метод проверяет ключ на правильность.
 * @param ws_key
 * @return Ключ
 * @throw cipher_error, если ключ пустой или невалидный
 */
inline std::wstring modAlphaCipher::getValidKey(const std::wstring & ws)
{
    if (ws.empty())
        throw cipher_error("Empty key");
    wstring tmp(ws);
    string s = codec.to_bytes(ws);
    for (auto & c:tmp) {
        if (!iswalpha(c)) {
            throw cipher_error(string("Invalid key ") + s);
        }
        if (iswlower(c))
            c = towupper(c);
    }
    return tmp;
}
/**
 * @brief Данный метод проверяет открытый текст на правильность.
 * Строчные буквы превращаются в прописные. Все символы, которые не буквы удаляются.
 * @param ws_open_text
 * @return Текст для расшифровки
 * @throw cipher_error, если текст пустой
 */
inline wstring modAlphaCipher::getValidOpenText(const wstring & ws)
{
    wstring tmp;
    for (auto c:ws) {
        if (iswalpha(c)) {
            if (iswlower(c))
                tmp.push_back(towupper(c));
            else
                tmp.push_back(c);
        }
    }
    if (tmp.empty())
        throw cipher_error("Empty open text");
    return tmp;
}
/**
 * @brief Данный метод проверяет зашифрованный текст на правильность.
 * @param ws_cipher_text
 * @return Зашифрованный текст
 * @throw cipher_error, если текст пустой или невалидный
 */
inline wstring modAlphaCipher::getValidCipherText(const wstring & ws)
{
    if (ws.empty())
        throw cipher_error("Empty cipher text");
    for (auto c:ws) {
        string s = codec.to_bytes(ws);
        if (!iswupper(c))
            throw cipher_error(string("Invalid cipher text ")+s);
    }
    return ws;
}
