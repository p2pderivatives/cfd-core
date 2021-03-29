// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_json_mapping_base.h
 *
 * @brief JSON-A file that defines the class mapping process.
 *
 * Create and use an inherited class.
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

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "univalue.h"  // NOLINT

namespace cfd {
namespace core {

// -----------------------------------------------------------------------------
// Class definition
// -----------------------------------------------------------------------------
/**
 * @brief Template structure for Get / Set / Type processing.
 */
template <typename T>
struct CLASS_FUNCTION_TABLE {
  std::function<std::string(const T&)> get_function;      //!< getter
  std::function<void(T&, const UniValue&)> set_function;  //!< setter
  std::function<std::string()> get_type_function;         //!< getter type
};

/**
 * @brief Mapping template for Json type processing
 */
template <class ClassName>
using JsonTableMap = std::map<std::string, CLASS_FUNCTION_TABLE<ClassName>>;

/**
 * @brief Performs character string conversion.
 * @param[in] value   Source value
 * @return Value after string conversion
 */
inline std::string ConvertToString(const uint32_t& value) {  // NOLINT
  UniValue json_value(static_cast<uint64_t>(value));
  std::string result = json_value.write();
  return result;
}

/**
 * @brief Performs character string conversion.
 * @param[in] value   Source value
 * @return Value after string conversion
 */
inline std::string ConvertToString(const uint64_t& value) {  // NOLINT
  return std::to_string(value);
}

/**
 * @brief Performs character string conversion.
 * @param[in] value   Source value
 * @return Value after string conversion
 */
template <typename T>
inline std::string ConvertToString(const T& value) {  // NOLINT
  UniValue json_value(static_cast<T>(value));
  std::string result = json_value.write();
  return result;
}

/**
 * @brief Convert from UniValue object to string type.
 * @param[out] value      Set value after conversion
 * @param[in] json_value  UniValue object
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
 * @brief Convert from UniValue object to bool type.
 * @param[out] value      Set value after conversion
 * @param[in] json_value  UniValue object
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
 * @brief Convert from UniValue object to double type.
 * @param[out] value      Set value after conversion
 * @param[in] json_value  UniValue object
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
 * @brief Convert from UniValue object to float type.
 * @param[out] value      Set value after conversion
 * @param[in] json_value  UniValue object
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
 * @brief Convert from UniValue object to unsigned 64bit type.
 * @param[out] value      Set value after conversion
 * @param[in] json_value  UniValue object
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
 * @brief Convert from UniValue object to template type.
 * @param[out] value      Set value after conversion
 * @param[in] json_value  UniValue object
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

// Template class (in template for JSON processing)
/**
 * @brief Base class for Json mapping transformation class.
 *
 * Define the inherited class using the macro at the bottom of this file.
 */
template <typename TYPE>
class JsonClassBase {
 public:
  /**
   * @brief Constructor.
   */
  JsonClassBase() {}
  /**
   * @brief Destructor.
   */
  virtual ~JsonClassBase() {}
  /**
   * @brief A function that is called before serialization begins.
   *
   * Override on the inherited class side if necessary.
   */
  virtual void PreSerialize() const {}
  /**
   * @brief A function called at the end of serialization.
   *
   * Override on the inherited class side if necessary.
   */
  virtual void PostSerialize() const {}
  /**
   * @brief A function that is called before deserialization begins.
   *
   * Override on the inherited class side if necessary.
   */
  virtual void PreDeserialize() {}
  /**
   * @brief A function called at the end of deserialization.
   *
   * Override on the inherited class side if necessary.
   */
  virtual void PostDeserialize() {}

  /**
   * @brief Performs serialization processing (JSON character string conversion).
   * @return JSON string
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
   * @brief Perform deserialization processing (JSON objectization).
   * @param[in] value   JSON string.
   */
  virtual void Deserialize(const std::string& value) {
    UniValue object;
    object.read(value);
    DeserializeUniValue(object);
  }

  /**
   * @brief Perform deserialization processing (JSON objectization).
   * @param[in] value   UniValue object.
   */
  virtual void DeserializeUniValue(const UniValue& value) {
    if (value.isArray()) {
      // If root is one list, take over to child class
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
   * @brief Get the JSON mapping object.
   *
   * Since the template is used, it is implemented on the \
   * inherited class side that has the actual situation.
   * @return JSON mapping object.
   */
  virtual const JsonTableMap<TYPE>& GetJsonMapper() const = 0;
  /**
   * @brief Get the JSON mapping item list.
   *
   * Get a list of target variable names according to the definition order.
   * Since the template is used, it is implemented on the inherited class \
   * side that has the actual situation.
   * @return JSON mapping item list.
   */
  virtual const std::vector<std::string>& GetJsonItemList() const = 0;
  /**
   * @brief Get a list of items to ignore during JSON mapping.
   *
   * Ignore the target variable when serializing.
   * Since the template is used, it is implemented on the \
   * inherited class side that has the actual situation.
   * @return Item list to ignore when JSON mapping
   */
  virtual const std::set<std::string>& GetIgnoreItem() const = 0;
};

/**
 * @brief Base class for Json mapping transformation list class.
 *
 * Define the inherited class using the macro at the bottom of this file.
 */
template <typename TYPE>
class JsonVector : public std::vector<TYPE> {
 public:
  /**
   * @brief Constructor.
   */
  JsonVector() {}
  /**
   * @brief Destructor.
   */
  virtual ~JsonVector() {}

  /**
   * @brief Substitution operator.
   * @param[in] obj   instance.
   * @return setting object.
   */
  TYPE& operator=(const TYPE& obj) {
    std::string serialize_string = obj.Serialize();
    Deserialize(serialize_string);
    return *this;
  }

  /**
   * @brief Performs serialization processing (JSON character string conversion).
   * @return JSON string
   */
  virtual std::string Serialize() const = 0;

  /**
   * @brief Perform deserialization processing (JSON objectization).
   * @param[in] value   JSON string
   */
  virtual void Deserialize(const std::string& value) {
    UniValue object;
    object.read(value);
    DeserializeUniValue(object);
  }

  /**
   * @brief Perform deserialization processing (JSON objectization).
   * @param[in] value   UniValue object
   */
  virtual void DeserializeUniValue(const UniValue& value) = 0;
};

/**
 * @brief Base class of Json mapping transformation list class for settings.
 *
 * Define the inherited class using the macro at the bottom of this file.
 */
template <typename TYPE>
class JsonValueVector : public JsonVector<TYPE> {
 public:
  /**
   * @brief Constructor.
   */
  JsonValueVector() {}
  /**
   * @brief Destructor.
   */
  virtual ~JsonValueVector() {}

  /**
   * @brief Performs serialization processing (JSON character string conversion).
   * @return JSON string.
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
   * @brief Perform deserialization processing (JSON objectization).
   * @param[in] value   UniValue object.
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
   * @brief Performs conversion processing from Struct information.
   * @param[in] list    List information
   */
  void ConvertFromStruct(const std::vector<TYPE>& list) {
    for (const auto& element : list) {
      std::vector<TYPE>::push_back(element);
    }
  }

  /**
   * @brief Performs conversion processing to Struct information.
   * @return Converted list information
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
 * @brief Base class for Json mapping transformation list classes for class objects.
 *
 * Define the inherited class using the macro at the bottom of this file.
 */
template <typename TYPE, typename STRUCT_TYPE>
class JsonObjectVector : public JsonVector<TYPE> {
 public:
  /**
   * @brief Constructor.
   */
  JsonObjectVector() {}
  /**
   * @brief Destructor.
   */
  virtual ~JsonObjectVector() {}

  /**
   * @brief Performs serialization processing (JSON character string conversion).
   * @return JSON string.
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
   * @brief Perform deserialization processing (JSON objectization).
   * @param[in] value   UniValue object
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
   * @brief Performs conversion processing from Struct information.
   * @param[in] list    List information
   */
  void ConvertFromStruct(const std::vector<STRUCT_TYPE>& list) {
    for (const auto& element : list) {
      TYPE object;
      object.ConvertFromStruct(element);
      std::vector<TYPE>::push_back(object);
    }
  }

  /**
   * @brief Performs conversion processing to Struct information.
   * @return Converted list information
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
