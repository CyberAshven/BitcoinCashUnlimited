package=native_protobuf
$(package)_version=3.19.4
$(package)_download_path=https://github.com/protocolbuffers/protobuf/releases/download/v$($(package)_version)/
$(package)_file_name=protobuf-cpp-$($(package)_version).tar.gz
$(package)_sha256_hash=89ac31a93832e204db6d73b1e80f39f142d5747b290f17340adce5be5b122f94

define $(package)_set_vars
$(package)_config_opts=--disable-shared
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) -j$(JOBS) -C src protoc
endef

define $(package)_stage_cmds
  $(MAKE) -C src DESTDIR=$($(package)_staging_dir) install-strip
endef

define $(package)_postprocess_cmds
  rm -rf lib include
endef
