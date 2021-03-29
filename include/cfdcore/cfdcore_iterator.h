// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_iterator.h
 *
 * @brief The Iterator Wrapper class definition
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ITERATOR_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ITERATOR_H_

#include <iterator>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_script.h"

namespace cfd {
namespace core {

/**
 * @brief Iterator's Wrapper class.
 */
template <class T>
class IteratorWrapper {
 public:
  /**
   * @brief constructor.
   * @details Create an iterator wrapper instance of the vector specified by the argument.
   * @param vector
   * @param error_message
   * @param is_reverse
   */
  IteratorWrapper(
      std::vector<T> vector, std::string error_message,
      bool is_reverse = false)
      : vector_(vector),
        iterator_(vector_.cbegin()),
        reverse_iterator_(vector_.crbegin()),
        error_message_(error_message),
        reverse_(is_reverse) {
    // do nothing
  }
  /**
   * @brief destructor.
   */
  virtual ~IteratorWrapper() {
    // do nothing
  }
  /**
   * @brief Returns whether the next element is available.
   * @retval true   When the next element is available
   * @retval false  When the next element cannot be obtained \
   *   (when the iterator points to the end)
   */
  bool hasNext() const {
    if (reverse_) {
      return reverse_iterator_ != vector_.crend();
    }
    return iterator_ != vector_.cend();
  }
  /**
   * @brief Returns whether the previous element is available.
   * @retval true   When the previous element is available
   * @retval false  When the previous element cannot be obtained \
   *    (when the iterator points to the beginning)
   */
  bool hasBack() const {
    if (reverse_) {
      return reverse_iterator_ != vector_.crbegin();
    }
    return iterator_ != vector_.cbegin();
  }
  /**
   * @brief Get the next element.
   * @return The next element of the current iterator
   */
  T next() {
    if (!hasNext()) {
      cfd::core::logger::warn(
          CFD_LOG_SOURCE,
          "Iterator reference out of range."
          " error_message={}.",
          error_message_);
      throw CfdException(kCfdOutOfRangeError, error_message_);
    }
    if (reverse_) {
      return *(reverse_iterator_++);
    }
    return *(iterator_++);
  }
  /**
   * @brief Get the previous element.
   * @return The next element of the current iterator
   */
  T back() {
    if (!hasBack()) {
      cfd::core::logger::warn(
          CFD_LOG_SOURCE,
          "Iterator reference out of range."
          " error_message={}.",
          error_message_);
      throw CfdException(kCfdOutOfRangeError, error_message_);
    }
    if (reverse_) {
      return *(reverse_iterator_--);
    }
    return *(iterator_--);
  }

 private:
  /**
   * @brief constructor(default constructor抑止)
   */
  IteratorWrapper();

  std::vector<T> vector_;                             ///< source vector
  typename std::vector<T>::const_iterator iterator_;  ///< forward iterator
  /// reverse iterator
  typename std::vector<T>::const_reverse_iterator reverse_iterator_;
  std::string error_message_;  ///< user error message
  bool reverse_;               ///< reverse iterator flag
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ITERATOR_H_
