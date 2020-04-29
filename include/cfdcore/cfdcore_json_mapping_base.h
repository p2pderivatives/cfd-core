// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_json_mapping_base.h
 *
 * @brief JSON-クラスマッピング処理を定義するファイル。
 *
 * 継承クラスを作成して利用する。
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_JSON_MAPPING_BASE_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_JSON_MAPPING_BASE_H_
#ifdef __cplusplus

#include <errno.h>
#include <stdint.h>
#include <functional>
#include <limits>
#include <list>
#include <map>
#include <set>
#include <string>
#include <type_traits>
#include <vector>

#include "univalue.h"  // NOLINT

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"

namespace cfd {
namespace core {

// -----------------------------------------------------------------------------
// クラス定義
// -----------------------------------------------------------------------------
/**
 * @brief Get/Set/Type処理用のテンプレート構造体
 */
template <typename T>
struct CLASS_FUNCTION_TABLE {
  std::function<std::string(const T&)> get_function;      //!< getter
  std::function<void(T&, const UniValue&)> set_function;  //!< setter
  std::function<std::string()> get_type_function;         //!< getter type
};

/**
 * @brief Json型処理を行うためのマッピングテンプレート
 */
template <class ClassName>
using JsonTableMap = std::map<std::string, CLASS_FUNCTION_TABLE<ClassName>>;

/**
 * @brief 文字列変換を行います。
 * @param[in] value   変換元の値
 * @return 文字列変換後の値
 */
inline std::string ConvertToString(const uint32_t& value) {  // NOLINT
  UniValue json_value(static_cast<uint64_t>(value));
  std::string result = json_value.write();
  return result;
}

/**
 * @brief 文字列変換を行います。
 * @param[in] value   変換元の値
 * @return 文字列変換後の値
 */
inline std::string ConvertToString(const uint64_t& value) {  // NOLINT
  return std::to_string(value);
}

/**
 * @brief 文字列変換を行います。
 * @param[in] value   変換元の値
 * @return 文字列変換後の値
 */
template <typename T>
inline std::string ConvertToString(const T& value) {  // NOLINT
  UniValue json_value(static_cast<T>(value));
  std::string result = json_value.write();
  return result;
}

/**
 * @brief UniValueオブジェクトからstring型に変換します。
 * @param[out] value      変換後の設定値
 * @param[in] json_value  UniValueオブジェクト
 */
inline void ConvertFromUniValue(
    std::string& value,            // NOLINT
    const UniValue& json_value) {  // NOLINT
  using cfd::core::CfdError;
  using cfd::core::CfdException;
  using cfd::core::logger::warn;
  if (json_value.isStr()) {
    value = json_value.getValStr();
  } else {
    warn(CFD_LOG_SOURCE, "Invalid json format.");
    throw CfdException(
        CfdError::kCfdOutOfRangeError,
        "Json value convert error. Invalid json format.");
  }
}

/**
 * @brief UniValueオブジェクトからbool型に変換します。
 * @param[out] value      変換後の設定値
 * @param[in] json_value  UniValueオブジェクト
 */
inline void ConvertFromUniValue(
    bool& value, const UniValue& json_value) {  // NOLINT
  using cfd::core::CfdError;
  using cfd::core::CfdException;
  using cfd::core::logger::warn;
  if (json_value.isBool()) {
    value = json_value.getBool();
  } else {
    warn(CFD_LOG_SOURCE, "Invalid json format.");
    throw CfdException(
        CfdError::kCfdOutOfRangeError,
        "Json value convert error. Invalid json format.");
  }
}

/**
 * @brief UniValueオブジェクトからdouble型に変換します。
 * @param[out] value      変換後の設定値
 * @param[in] json_value  UniValueオブジェクト
 */
inline void ConvertFromUniValue(
    double& value, const UniValue& json_value) {  // NOLINT
  using cfd::core::CfdError;
  using cfd::core::CfdException;
  using cfd::core::logger::warn;
  if (json_value.isNum()) {
    value = json_value.get_real();
  } else {
    warn(CFD_LOG_SOURCE, "Invalid json format.");
    throw CfdException(
        CfdError::kCfdOutOfRangeError,
        "Json value convert error. Invalid json format.");
  }
}

/**
 * @brief UniValueオブジェクトからfloat型に変換します。
 * @param[out] value      変換後の設定値
 * @param[in] json_value  UniValueオブジェクト
 */
inline void ConvertFromUniValue(
    float& value, const UniValue& json_value) {  // NOLINT
  using cfd::core::CfdError;
  using cfd::core::CfdException;
  using cfd::core::logger::warn;
  if (json_value.isNum()) {
    value = static_cast<float>(json_value.get_real());
  } else {
    warn(CFD_LOG_SOURCE, "Invalid json format.");
    throw CfdException(
        CfdError::kCfdOutOfRangeError,
        "Json value convert error. Invalid json format.");
  }
}

/**
 * @brief UniValueオブジェクトからfloat型に変換します。
 * @param[out] value      変換後の設定値
 * @param[in] json_value  UniValueオブジェクト
 */
inline void ConvertFromUniValue(
    uint64_t& value, const UniValue& json_value) {  // NOLINT
  using cfd::core::CfdError;
  using cfd::core::CfdException;
  using cfd::core::logger::warn;
  if (json_value.isStr() || json_value.isNum()) {
    std::string str = json_value.getValStr();
    if (str == "0n") {
      str = "0";
    }
    bool is_digits_only = std::all_of(str.begin(), str.end(), ::isdigit);
    if (!is_digits_only || str.empty()) {
      warn(CFD_LOG_SOURCE, "Invalid json_value. : json_value={}", str);
      throw CfdException(
          CfdError::kCfdOutOfRangeError,
          "Json value convert error. Value out of range.");
    }

    char* endp = NULL;
    errno = 0;
    value = static_cast<uint64_t>(std::strtoull(str.c_str(), &endp, 10));
    if ((errno == ERANGE) || ((endp != nullptr) && (*endp != '\0'))) {
      errno = 0;
      warn(CFD_LOG_SOURCE, "Invalid json_value. : json_value={}", value);
      throw CfdException(
          CfdError::kCfdOutOfRangeError,
          "Json value convert error. Value out of range.");
    }
  } else {
    warn(CFD_LOG_SOURCE, "Invalid json format.");
    throw CfdException(
        CfdError::kCfdOutOfRangeError,
        "Json value convert error. Invalid json format.");
  }
}

/**
 * @brief UniValueオブジェクトから指定された型に変換します。
 * @param[out] value      変換後の設定値
 * @param[in] json_value  UniValueオブジェクト
 */
template <typename T>
inline void ConvertFromUniValue(
    T& value, const UniValue& json_value) {  // NOLINT
  using cfd::core::CfdError;
  using cfd::core::CfdException;
  using cfd::core::logger::warn;
  UniValue json_value_copy = json_value;
  if (json_value_copy.isStr()) {
    auto str = json_value.get_str();
    if (str == "0n") {
      json_value_copy = UniValue(UniValue::VNUM, "0");
    } else {
      auto begin_pos = str.begin();
      if (*begin_pos == '-') ++begin_pos;
      bool is_digits_only = std::all_of(begin_pos, str.end(), ::isdigit);
      // check max of int64 : execute call get_int64()
      if (is_digits_only) {
        json_value_copy = UniValue(UniValue::VNUM, json_value.get_str());
      }
    }
  }

  if (json_value_copy.isNum()) {
    const int64_t num = json_value_copy.get_int64();
    if (std::is_unsigned<T>::value) {
      uint64_t unsigned_num = static_cast<uint64_t>(num);
      uint64_t maximum = static_cast<uint64_t>(std::numeric_limits<T>::max());
      if ((num < 0) || (maximum < unsigned_num)) {
        warn(CFD_LOG_SOURCE, "Invalid json_value. : json_value={}", num);
        throw CfdException(
            CfdError::kCfdOutOfRangeError,
            "Json value convert error. Value out of range.");
      }
    } else {
      int64_t maximum = static_cast<int64_t>(std::numeric_limits<T>::max());
      int64_t minimum = static_cast<int64_t>(std::numeric_limits<T>::min());
      if ((maximum < num) || (minimum > num)) {
        warn(CFD_LOG_SOURCE, "Invalid json_value. : json_value={}", num);
        throw CfdException(
            CfdError::kCfdOutOfRangeError,
            "Json value convert error. Value out of range.");
      }
    }
    value = static_cast<T>(num);
  } else {
    warn(CFD_LOG_SOURCE, "Invalid json format.");
    throw CfdException(
        CfdError::kCfdOutOfRangeError,
        "Json value convert error. Invalid json format.");
  }
}

// テンプレートクラス（JSON処理のためテンプレートに）
/**
 * @brief Jsonマッピング変換クラスのベースクラス。
 *
 * 本ファイル下部のマクロを利用して継承クラスを定義する。
 */
template <typename TYPE>
class JsonClassBase {
 public:
  /**
   * @brief コンストラクタ
   */
  JsonClassBase() {}
  /**
   * @brief デストラクタ
   */
  virtual ~JsonClassBase() {}
  /**
   * @brief シリアライズ開始前にコールされる関数。
   *
   * 必要に応じて継承クラス側でオーバーライドする。
   */
  virtual void PreSerialize() const {}
  /**
   * @brief シリアライズ終了時にコールされる関数。
   *
   * 必要に応じて継承クラス側でオーバーライドする。
   */
  virtual void PostSerialize() const {}
  /**
   * @brief デシリアライズ開始前にコールされる関数。
   *
   * 必要に応じて継承クラス側でオーバーライドする。
   */
  virtual void PreDeserialize() {}
  /**
   * @brief デシリアライズ終了時にコールされる関数。
   *
   * 必要に応じて継承クラス側でオーバーライドする。
   */
  virtual void PostDeserialize() {}

  /**
   * @brief シリアライズ処理（JSON文字列化）を行う。
   * @return JSON文字列
   */
  virtual std::string Serialize() const {
    PreSerialize();

    std::string result;
    JsonTableMap<TYPE> mapper = GetJsonMapper();
    std::list<std::string> str_list;
    const std::vector<std::string>& key_list = GetJsonItemList();
    const std::set<std::string>& ignore_items = GetIgnoreItem();
    for (const std::string& key : key_list) {
      if (ignore_items.find(key) != ignore_items.end()) {
        continue;
      }
      std::string item_result = "\"" + key + "\":";
      item_result +=
          mapper[key].get_function(*(reinterpret_cast<const TYPE*>(this)));
      str_list.push_back(item_result);
    }

    result = "{";
    bool is_first = true;
    for (const auto& item : str_list) {
      if (!is_first) {
        result += ",";
      }
      result += item;
      is_first = false;
    }
    result += "}";

    PostSerialize();
    return result;
  }

  /**
   * @brief デシリアライズ処理（JSONオブジェクト化）を行う。
   * @param[in] value   JSON文字列
   */
  virtual void Deserialize(const std::string& value) {
    UniValue object;
    object.read(value);
    DeserializeUniValue(object);
  }

  /**
   * @brief デシリアライズ処理（JSONオブジェクト化）を行う。
   * @param[in] value   UniValueオブジェクト
   */
  virtual void DeserializeUniValue(const UniValue& value) {
    if (value.isArray()) {
      // rootがリスト1つの場合、子クラスに引継ぎ
      JsonTableMap<TYPE> mapper = GetJsonMapper();
      if (mapper.size() == 1) {
        PreDeserialize();
        auto iter = mapper.begin();
        if (iter != end(mapper)) {
          CLASS_FUNCTION_TABLE<TYPE>* table_info = &iter->second;
          table_info->set_function(*(reinterpret_cast<TYPE*>(this)), value);
        }
        PostDeserialize();
      }
      return;
    } else if (!value.isObject()) {
      return;
    }
    PreDeserialize();
    JsonTableMap<TYPE> mapper = GetJsonMapper();
    std::map<std::string, UniValue> json_map;
    value.getObjMap(json_map);
    for (const auto& child : json_map) {
      auto iter = mapper.find(child.first);
      if (iter != end(mapper)) {
        CLASS_FUNCTION_TABLE<TYPE>* table_info = &iter->second;
        table_info->set_function(
            *(reinterpret_cast<TYPE*>(this)), child.second);
      }
    }
    PostDeserialize();
  }

 protected:
  /**
   * @brief JSONマッピングオブジェクトを取得する。
   *
   * テンプレートを用いる関係上、実態を有する継承クラス側で実装する。
   * @return JSONマッピングオブジェクト
   */
  virtual const JsonTableMap<TYPE>& GetJsonMapper() const = 0;
  /**
   * @brief JSONマッピングのアイテム一覧を取得する。
   *
   * 対象の変数名を、定義順序に従い一覧取得する。
   * テンプレートを用いる関係上、実態を有する継承クラス側で実装する。
   * @return JSONマッピングのアイテム一覧
   */
  virtual const std::vector<std::string>& GetJsonItemList() const = 0;
  /**
   * @brief JSONマッピング時に無視するアイテム一覧を取得する。
   *
   * Serialize時に対象の変数を無視する。
   * テンプレートを用いる関係上、実態を有する継承クラス側で実装する。
   * @return JSONマッピング時に無視するアイテム一覧
   */
  virtual const std::set<std::string>& GetIgnoreItem() const = 0;
};

/**
 * @brief Jsonマッピング変換リストクラスのベースクラス。
 *
 * 本ファイル下部のマクロを利用して継承クラスを定義する。
 */
template <typename TYPE>
class JsonVector : public std::vector<TYPE> {
 public:
  /**
   * @brief コンストラクタ
   */
  JsonVector() {}
  /**
   * @brief デストラクタ
   */
  virtual ~JsonVector() {}

  /**
   * @brief オペレーター（代入）
   * @param[in] obj   代入する側のインスタンス
   * @return 代入される側のインスタンス
   */
  TYPE& operator=(const TYPE& obj) {
    std::string serialize_string = obj.Serialize();
    Deserialize(serialize_string);
    return *this;
  }

  /**
   * @brief シリアライズ処理（JSON文字列化）を行う。
   * @return JSON文字列
   */
  virtual std::string Serialize() const = 0;

  /**
   * @brief デシリアライズ処理（JSONオブジェクト化）を行う。
   * @param[in] value   JSON文字列
   */
  virtual void Deserialize(const std::string& value) {
    UniValue object;
    object.read(value);
    DeserializeUniValue(object);
  }

  /**
   * @brief デシリアライズ処理（JSONオブジェクト化）を行う。
   * @param[in] value   UniValueオブジェクト
   */
  virtual void DeserializeUniValue(const UniValue& value) = 0;
};

/**
 * @brief 設定値用のJsonマッピング変換リストクラスのベースクラス。
 *
 * 本ファイル下部のマクロを利用して継承クラスを定義する。
 */
template <typename TYPE>
class JsonValueVector : public JsonVector<TYPE> {
 public:
  /**
   * @brief コンストラクタ
   */
  JsonValueVector() {}
  /**
   * @brief デストラクタ
   */
  virtual ~JsonValueVector() {}

  /**
   * @brief シリアライズ処理（JSON文字列化）を行う。
   * @return JSON文字列
   */
  virtual std::string Serialize() const {
    std::string result;
    std::list<std::string> str_list;
    for (const auto& element : *this) {
      std::string item_result = ConvertToString(element);
      str_list.push_back(item_result);
    }

    result = "[";
    bool is_first = true;
    for (const auto& item : str_list) {
      if (!is_first) {
        result += ",";
      }
      result += item;
      is_first = false;
    }
    result += "]";

    return result;
  }

  /**
   * @brief デシリアライズ処理（JSONオブジェクト化）を行う。
   * @param[in] value   UniValueオブジェクト
   */
  virtual void DeserializeUniValue(const UniValue& value) {
    if (!value.isArray()) {
      return;
    }
    std::vector<TYPE>::clear();
    for (const auto& element : value.getValues()) {
      if (!element.isObject()) {
        TYPE type_value;
        ConvertFromUniValue(type_value, element);
        std::vector<TYPE>::push_back(type_value);
      }
    }
  }

  /**
   * @brief Struct情報からの変換処理を行う。
   * @param[in] list    リスト情報
   */
  void ConvertFromStruct(const std::vector<TYPE>& list) {
    for (const auto& element : list) {
      std::vector<TYPE>::push_back(element);
    }
  }

  /**
   * @brief Struct情報への変換処理を行う。
   * @return 変換済みリスト情報
   */
  std::vector<TYPE> ConvertToStruct() const {
    std::vector<TYPE> result;
    for (const auto& element : *this) {
      TYPE value = element;
      result.push_back(value);
    }
    return result;
  }
};

/**
 * @brief クラスオブジェクト用のJsonマッピング変換リストクラスのベースクラス。
 *
 * 本ファイル下部のマクロを利用して継承クラスを定義する。
 */
template <typename TYPE, typename STRUCT_TYPE>
class JsonObjectVector : public JsonVector<TYPE> {
 public:
  /**
   * @brief コンストラクタ
   */
  JsonObjectVector() {}
  /**
   * @brief デストラクタ
   */
  virtual ~JsonObjectVector() {}

  /**
   * @brief シリアライズ処理（JSON文字列化）を行う。
   * @return JSON文字列
   */
  virtual std::string Serialize() const {
    std::string result;
    std::list<std::string> str_list;
    for (auto& element : *this) {
      std::string item = element.Serialize();
      str_list.push_back(item);
    }

    result = "[";
    bool is_first = true;
    for (const auto& item : str_list) {
      if (!is_first) {
        result += ",";
      }
      result += item;
      is_first = false;
    }
    result += "]";

    return result;
  }

  /**
   * @brief デシリアライズ処理（JSONオブジェクト化）を行う。
   * @param[in] value   UniValueオブジェクト
   */
  virtual void DeserializeUniValue(const UniValue& value) {
    if (!value.isArray()) {
      return;
    }
    std::vector<TYPE>::clear();
    for (const auto& element : value.getValues()) {
      if (element.isObject()) {
        TYPE local_value;
        local_value.DeserializeUniValue(element);
        std::vector<TYPE>::push_back(local_value);
      }
    }
  }

  /**
   * @brief Struct情報からの変換処理を行う。
   * @param[in] list    リスト情報
   */
  void ConvertFromStruct(const std::vector<STRUCT_TYPE>& list) {
    for (const auto& element : list) {
      TYPE object;
      object.ConvertFromStruct(element);
      std::vector<TYPE>::push_back(object);
    }
  }

  /**
   * @brief Struct情報への変換処理を行う。
   * @return 変換済みリスト情報
   */
  std::vector<STRUCT_TYPE> ConvertToStruct() const {
    std::vector<STRUCT_TYPE> result;
    for (const auto& element : *this) {
      STRUCT_TYPE data = element.ConvertToStruct();
      result.push_back(data);
    }
    return result;
  }
};

}  // namespace core
}  // namespace cfd

#endif  // __cplusplus
#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_JSON_MAPPING_BASE_H_
