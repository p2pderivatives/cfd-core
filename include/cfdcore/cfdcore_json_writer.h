// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_json_writer.h
 *
 * @brief JSON文字列の生成時に使用にするクラスを定義する。
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_JSON_WRITER_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_JSON_WRITER_H_

#include <initializer_list>
#include <string>

#include "univalue.h"  // NOLINT

namespace cfd {
namespace core {

/**
 * @brief Json生成時に利用するクラス。
 */
class JsonElement {
 public:
  /**
   * @brief コンストラクタ
   * @param[in] key キー値
   */
  explicit JsonElement(std::string key) : key_(key), value_() {}
  /**
   * @brief コンストラクタ
   * @param[in] key     キー値
   * @param[in] object  エレメントオブジェクト
   */
  JsonElement(std::string key, const JsonElement& object)
      : key_(key), value_(UniValue::VOBJ) {
    value_.push_back(object.GetUnivalue());
  }
  /**
   * @brief コンストラクタ
   * @param[in] value   UniValueオブジェクト
   */
  explicit JsonElement(const UniValue& value) : key_(), value_(value) {}
  /**
   * @brief コンストラクタ
   * @param[in] key     キー値
   * @param[in] value   UniValueオブジェクト
   */
  JsonElement(std::string key, const UniValue& value)
      : key_(key), value_(value) {}
  /**
   * @brief コンストラクタ
   * @param[in] key     キー値
   * @param[in] value   設定値
   */
  template <typename TYPE>
  JsonElement(std::string key, TYPE value) : key_(key), value_(value) {}
  /**
   * @brief デストラクタ
   */
  virtual ~JsonElement() {}

  /**
   * @brief キー値を設定する。
   * @param[in] key     キー値
   */
  void SetKey(const std::string& key) { key_ = key; }
  /**
   * @brief キー値を取得する。
   * @return キー値
   */
  const std::string& GetKey() const { return key_; }
  /**
   * @brief UniValue値を取得する。
   * @return UniValueオブジェクト
   */
  const UniValue& GetUnivalue() const { return value_; }

 protected:
  std::string key_;  ///< キー値
  UniValue value_;   ///< UniValueオブジェクト
};

/**
 * @brief Json生成用クラス。
 *
 * Json生成のみ対応。Json文字列からの変換には対応せず。
 *
 * イメージ（テスト実装）
 * @code
 * JsonBuilder jb;
 * jb.Set(
 *     jb.Str("name", "Joe"),
 *     jb.Num("age",20),
 *     jb.Array("children",
 *         jb.ObjectV(
 *             jb.Str("name","john"),
 *             jb.Num("age", 8)
 *         ),
 *         jb.ObjectV(
 *             jb.Str("name","beth"),
 *             jb.Num("age", 9)
 *         )
 *     ),
 *     jb.Object("notification",
 *         jb.Bool("slack", true),
 *         jb.Bool("sms", false)
 *     )
 * );
 * std::cout << "object = " << jb.Build() << std::endl;
 * @endcode
 */
class JsonBuilder {
  /**
   * @brief JsonElementの初期化子リスト
   */
  using JsonElementInitialize = std::initializer_list<JsonElement>;

 public:
  /**
   * @brief コンストラクタ
   */
  JsonBuilder() : root_() {}
  /**
   * @brief デストラクタ
   */
  virtual ~JsonBuilder() {}

  /**
   * @brief ルートに指定されたエレメントを設定する。
   * @param[in] value     JsonElementオブジェクト
   * @param[in] args    可変引数（JsonElementオブジェクト）
   */
  template <class... Args>
  void Set(const JsonElement& value, Args&&... args) {
    if (value.GetKey().empty()) {
      // for array
      root_.setArray();
      root_.push_back(value.GetUnivalue());
      for (const JsonElement& object : JsonElementInitialize{args...}) {
        root_.push_back(object.GetUnivalue());
      }
    } else {
      root_.setObject();
      root_.pushKV(value.GetKey(), value.GetUnivalue());
      for (const JsonElement& object : JsonElementInitialize{args...}) {
        root_.pushKV(object.GetKey(), object.GetUnivalue());
      }
    }
  }

  /**
   * @brief JSON文字列を生成する。
   * @param[in] indent    Indent値。0は整形なし（１行出力）。1以上は整形＋指定値分Indentする。
   * @return JSON文字列
   */
  std::string Build(int indent = 0) {
    // IndentLevel(writeの第二引数)はどうも((indent-1)*IndentLevel)分だけ2行目以降のIndentに加算するので、変えない方がいい。
    // 固定値加算ならともかく、なぜに乗算。
    return root_.write(indent);
  }

  /**
   * @brief 文字列型を生成する。
   * @param[in] key     キー値
   * @param[in] value     JsonElementオブジェクト
   * @return 文字列型を設定したJsonElement
   */
  JsonElement Str(std::string key, const JsonElement& value) {
    return JsonElement(key, value.GetUnivalue());
  }
  /**
   * @brief 文字列型を生成する。
   * @param[in] key     キー値
   * @param[in] value     stringオブジェクト
   * @return 文字列型を設定したJsonElement
   */
  JsonElement Str(std::string key, const std::string& value) {
    return JsonElement(key, value);
  }

  /**
   * @brief 数値型を生成する。
   * @param[in] key     キー値
   * @param[in] value     JsonElementオブジェクト
   * @return 数値型を設定したJsonElement
   */
  JsonElement Num(std::string key, const JsonElement& value) {
    return JsonElement(key, value.GetUnivalue());
  }
  /**
   * @brief 数値列型を生成する。
   * @param[in] key     キー値
   * @param[in] value     数値型の値
   * @return 数値型を設定したJsonElement
   */
  template <typename TYPE>
  JsonElement Num(std::string key, TYPE value) {
    return JsonElement(key, value);
  }

  /**
   * @brief bool型を生成する。
   * @param[in] key     キー値
   * @param[in] value     JsonElementオブジェクト
   * @return bool型を設定したJsonElement
   */
  JsonElement Bool(std::string key, const JsonElement& value) {
    return JsonElement(key, value.GetUnivalue());
  }
  /**
   * @brief bool型を生成する。
   * @param[in] key       キー値
   * @param[in] is_true   bool値
   * @return bool型を設定したJsonElement
   */
  JsonElement Bool(std::string key, bool is_true) {
    return JsonElement(key, is_true);
  }

  /**
   * @brief オブジェクト型を生成する。
   * @param[in] key     キー値
   * @param[in] args    オブジェクト型に設定するJsonElementオブジェクト
   * @return オブジェクト型を設定したJsonElement
   */
  template <class... Args>
  JsonElement Object(std::string key, Args&&... args) {
    UniValue elem(UniValue::VOBJ);
    for (const JsonElement& object : JsonElementInitialize{args...})
      elem.pushKV(object.GetKey(), object.GetUnivalue());
    return JsonElement(key, elem);
  }

  /**
   * @brief Array型を生成する。
   * @param[in] key     キー値
   * @param[in] args    Array型に設定するJsonElementオブジェクト
   * @return Array型を設定したJsonElement
   */
  template <class... Args>
  JsonElement Array(std::string key, Args&&... args) {
    UniValue elem(UniValue::VARR);
    for (const JsonElement& object : JsonElementInitialize{args...})
      elem.push_back(object.GetUnivalue());
    return JsonElement(key, elem);
  }

  /**
   * @brief 文字列型を生成する。
   * @param[in] value     JsonElementオブジェクト
   * @return 文字列型を設定したJsonElement
   */
  JsonElement StrV(const JsonElement& value) { return Str("", value); }
  /**
   * @brief 文字列型を生成する。
   * @param[in] value     stringオブジェクト
   * @return 文字列型を設定したJsonElement
   */
  JsonElement StrV(const std::string& value) { return Str("", value); }

  /**
   * @brief 数値型を生成する。
   * @param[in] value     JsonElementオブジェクト
   * @return 数値型を設定したJsonElement
   */
  JsonElement NumV(const JsonElement& value) { return Num("", value); }
  /**
   * @brief 数値列型を生成する。
   * @param[in] value     数値型の値
   * @return 数値型を設定したJsonElement
   */
  template <typename TYPE>
  JsonElement NumV(TYPE value) {
    return Num("", value);
  }

  /**
   * @brief bool型を生成する。
   * @param[in] value     JsonElementオブジェクト
   * @return bool型を設定したJsonElement
   */
  JsonElement BoolV(const JsonElement& value) { return Bool("", value); }
  /**
   * @brief bool型を生成する。
   * @param[in] is_true   bool値
   * @return bool型を設定したJsonElement
   */
  JsonElement BoolV(bool is_true) { return Bool("", is_true); }

  /**
   * @brief オブジェクト型を生成する。
   * @param[in] args    オブジェクト型に設定するJsonElementオブジェクト
   * @return オブジェクト型を設定したJsonElement
   */
  template <class... Args>
  JsonElement ObjectV(Args&&... args) {
    UniValue elem(UniValue::VOBJ);
    for (const JsonElement& object : JsonElementInitialize{args...})
      elem.pushKV(object.GetKey(), object.GetUnivalue());
    return JsonElement(elem);
  }

  /**
   * @brief Array型を生成する。
   * @param[in] args    Array型に設定するJsonElementオブジェクト
   * @return Array型を設定したJsonElement
   */
  template <class... Args>
  JsonElement ArrayV(Args&&... args) {
    UniValue elem(UniValue::VARR);
    for (const JsonElement& object : JsonElementInitialize{args...})
      elem.push_back(object.GetUnivalue());
    return JsonElement(elem);
  }

 private:
  UniValue root_;  ///< UniValueオブジェクト
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_JSON_WRITER_H_
