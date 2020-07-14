local change: spdlog/fmt/bundled/format.h, class basic_memory_buffer
diff:
```
  explicit basic_memory_buffer(const Allocator& alloc = Allocator())
      : Allocator(alloc) {
+   memset(store_, 0, sizeof(store_));  // TODO(k-matsuzawa): append
    this->set(store_, SIZE);
  }
```

```
  void move(basic_memory_buffer& other) {
    Allocator &this_alloc = *this, &other_alloc = other;
    this_alloc = std::move(other_alloc);
    T* data = other.data();
    std::size_t size = other.size(), capacity = other.capacity();
    if (data == other.store_) {
      this->set(store_, capacity);
+     memset(store_, 0, sizeof(store_));  // TODO(k-matsuzawa): append
      std::uninitialized_copy(other.store_, other.store_ + size,
                              internal::make_checked(store_, capacity));
    } else {
      this->set(data, capacity);
      // Set pointer to the inline array so that delete is not called
      // when deallocating.
      other.set(other.store_, 0);
    }
    this->resize(size);
  }
```

```
  basic_memory_buffer(basic_memory_buffer&& other) FMT_NOEXCEPT {
+   memset(store_, 0, sizeof(store_));  // TODO(k-matsuzawa): append
    move(other);
  }

```

