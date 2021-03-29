// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_json_writer.h
 *
 * @brief Define the class to be used when generating the JSON string.
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_JSON_WRITER_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_JSON_WRITER_H_

#include <initializer_list>
#include <string>

#include "univalue.h"  // NOLINT

namespace cfd {
namespace core {

/**
 * @brief Class used when generating Json.
 */
class JsonElement {
 public:
  /**
   * @brief Constructor.
   * @param[in] key   key
   */
  explicit JsonElement(std::string key) : key_(key), value_() {}
  /**
   * @brief Constructor.
   * @param[in] key     key
   * @param[in] object  element object
   */
  JsonElement(std::string key, const JsonElement& object)
      : key_(key), value_(UniValue::VOBJ) {
    value_.push_back(object.GetUnivalue());
  }
  /**
   * @brief Constructor.
   * @param[in] value   UniValue object
   */
  explicit JsonElement(const UniValue& value) : key_(), value_(value) {}
  /**
   * @brief Constructor.
   * @param[in] key     key
   * @param[in] value   UniValue object
   */
  JsonElement(std::string key, const UniValue& value)
      : key_(key), value_(value) {}
  /**
   * @brief Constructor.
   * @param[in] key     key
   * @param[in] value   value
   */
  template <typename TYPE>
  JsonElement(std::string key, TYPE value) : key_(key), value_(value) {}
  /**
   * @brief destructor.
   */
  virtual ~JsonElement() {}

  /**
   * @brief Set the key.
   * @param[in] key     key
   */
  void SetKey(const std::string& key) { key_ = key; }
  /**
   * @brief Get the key.
   * @return key
   */
  const std::string& GetKey() const { return key_; }
  /**
   * @brief Get the UniValue object.
   * @return UniValue object
   */
  const UniValue& GetUnivalue() const { return value_; }

 protected:
  std::string key_;  ///< key
  UniValue value_;   ///< UniValue object
};

/**
 * @brief Json generation class.
 *
 * Only Json generation is supported.
 * Does not support conversion from Json strings.
 *
 * Image (test implementation):
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
   * @brief JsonElement initializer list
   */
  using JsonElementInitialize = std::initializer_list<JsonElement>;

 public:
  /**
   * @brief Constructor.
   */
  JsonBuilder() : root_() {}
  /**
   * @brief Destructor.
   */
  virtual ~JsonBuilder() {}

  /**
   * @brief Set the element specified in the root.
   * @param[in] value   JsonElement object
   * @param[in] args    Variadic argument (JsonElement object)
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
   * @brief Generate a JSON string.
   * @param[in] indent    Indent value. \
   *    0 is no formatting (1 line output). \
   *    1 or more is shaped + indented by the specified value.
   * @return JSON string
   */
  std::string Build(int indent = 0) {
    // IndentLevel (second argument of write function) is added to \
    // Indent on the second and subsequent lines by \
    // ((indent-1) * IndentLevel), so it is better not to change it.
    // Why is it multiplying rather than adding at a fixed value.
    return root_.write(indent);
  }

  /**
   * @brief Generate a string type.
   * @param[in] key     key
   * @param[in] value     JsonElement object
   * @return JsonElement with string type set
   */
  JsonElement Str(std::string key, const JsonElement& value) {
    return JsonElement(key, value.GetUnivalue());
  }
  /**
   * @brief Generate a string type.
   * @param[in] key     key
   * @param[in] value     string object
   * @return JsonElement with string type set
   */
  JsonElement Str(std::string key, const std::string& value) {
    return JsonElement(key, value);
  }

  /**
   * @brief Generate a numeric type.
   * @param[in] key     key
   * @param[in] value     JsonElement object
   * @return JsonElement with numeric type
   */
  JsonElement Num(std::string key, const JsonElement& value) {
    return JsonElement(key, value.GetUnivalue());
  }
  /**
   * @brief Generate a numeric type.
   * @param[in] key     key
   * @param[in] value     Numeric value
   * @return JsonElement with numeric type
   */
  template <typename TYPE>
  JsonElement Num(std::string key, TYPE value) {
    return JsonElement(key, value);
  }

  /**
   * @brief Generate a bool type.
   * @param[in] key     key
   * @param[in] value     JsonElement object
   * @return JsonElement with bool type
   */
  JsonElement Bool(std::string key, const JsonElement& value) {
    return JsonElement(key, value.GetUnivalue());
  }
  /**
   * @brief Generate a bool type.
   * @param[in] key       key
   * @param[in] is_true   bool value
   * @return JsonElement with bool type
   */
  JsonElement Bool(std::string key, bool is_true) {
    return JsonElement(key, is_true);
  }

  /**
   * @brief Generate an object type.
   * @param[in] key     key
   * @param[in] args    JsonElement object to set to object type
   * @return JsonElement with object type set
   */
  template <class... Args>
  JsonElement Object(std::string key, Args&&... args) {
    UniValue elem(UniValue::VOBJ);
    for (const JsonElement& object : JsonElementInitialize{args...})
      elem.pushKV(object.GetKey(), object.GetUnivalue());
    return JsonElement(key, elem);
  }

  /**
   * @brief Generate Array type.
   * @param[in] key     key
   * @param[in] args    JsonElement object set to Array type
   * @return JsonElement with Array type set
   */
  template <class... Args>
  JsonElement Array(std::string key, Args&&... args) {
    UniValue elem(UniValue::VARR);
    for (const JsonElement& object : JsonElementInitialize{args...})
      elem.push_back(object.GetUnivalue());
    return JsonElement(key, elem);
  }

  /**
   * @brief Generate a string type.
   * @param[in] value     JsonElement object
   * @return JsonElement with string type set
   */
  JsonElement StrV(const JsonElement& value) { return Str("", value); }
  /**
   * @brief Generate a string type.
   * @param[in] value     string object
   * @return JsonElement with string type set
   */
  JsonElement StrV(const std::string& value) { return Str("", value); }

  /**
   * @brief Generate a numeric type.
   * @param[in] value     JsonElement object
   * @return JsonElement with numeric type
   */
  JsonElement NumV(const JsonElement& value) { return Num("", value); }
  /**
   * @brief Generate a numeric type.
   * @param[in] value     Numeric value
   * @return JsonElement with numeric type
   */
  template <typename TYPE>
  JsonElement NumV(TYPE value) {
    return Num("", value);
  }

  /**
   * @brief Generate a bool type.
   * @param[in] value     JsonElement object
   * @return JsonElement with bool type
   */
  JsonElement BoolV(const JsonElement& value) { return Bool("", value); }
  /**
   * @brief Generate a bool type.
   * @param[in] is_true   bool value
   * @return JsonElement with bool type
   */
  JsonElement BoolV(bool is_true) { return Bool("", is_true); }

  /**
   * @brief Generate an object type.
   * @param[in] args    JsonElement object set to object type
   * @return JsonElement with object type set
   */
  template <class... Args>
  JsonElement ObjectV(Args&&... args) {
    UniValue elem(UniValue::VOBJ);
    for (const JsonElement& object : JsonElementInitialize{args...})
      elem.pushKV(object.GetKey(), object.GetUnivalue());
    return JsonElement(elem);
  }

  /**
   * @brief Generate Array type.
   * @param[in] args    JsonElement object set to Array type
   * @return JsonElement with Array type set
   */
  template <class... Args>
  JsonElement ArrayV(Args&&... args) {
    UniValue elem(UniValue::VARR);
    for (const JsonElement& object : JsonElementInitialize{args...})
      elem.push_back(object.GetUnivalue());
    return JsonElement(elem);
  }

 private:
  UniValue root_;  ///< UniValue object
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_JSON_WRITER_H_
