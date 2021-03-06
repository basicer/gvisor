#!/bin/bash

# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Fail on any error. Treat unset variables as error. Print commands as executed.
set -eux


###################
# GLOBAL ENV VARS #
###################

readonly WORKSPACE_DIR="${PWD}/git/repo"

# Random runtime name to avoid collisions.
readonly RUNTIME="runsc_test_$((RANDOM))"


#######################
# BAZEL CONFIGURATION #
#######################

# Install the latest version of Bazel, and log the location and version.
use_bazel.sh latest
which bazel
bazel version


####################
# Helper Functions #
####################

build_everything() {
  cd ${WORKSPACE_DIR}
  # TODO: Include "test" directory.
  bazel build //pkg/... //runsc/... //tools/...
}

# Run simple tests runs the tests that require no special setup or
# configuration.
run_simple_tests() {
  cd ${WORKSPACE_DIR}
  # TODO: Include "test" directory.
  bazel test --test_output=errors //pkg/... //runsc/... //tools/...
}

install_runtime() {
  cd ${WORKSPACE_DIR}
  sudo -n ${WORKSPACE_DIR}/runsc/test/install.sh --runtime ${RUNTIME}
}

# Install dependencies for the crictl tests.
install_crictl_test_deps() {
  # Install containerd.
  # libseccomp2 needs to be downgraded in order to install libseccomp-dev.
  sudo -n -E apt-get install -y --force-yes libseccomp2=2.1.1-1ubuntu1~trusty4
  sudo -n -E apt-get install -y btrfs-tools libseccomp-dev
  # go get will exit with a status of 1 despite succeeding, so ignore errors.
  go get -d github.com/containerd/containerd || true
  cd ${GOPATH}/src/github.com/containerd/containerd
  # TODO: Switch to using a tagged version once one has been cut
  # that contains fix in:
  # https://github.com/containerd/containerd/commit/52de3717005eb20141c305bd93ff0d6ee5dfecb6
  git checkout master
  make
  sudo -n -E make install

  # Install crictl.
  # go get will exit with a status of 1 despite succeeding, so ignore errors.
  go get -d github.com/kubernetes-sigs/cri-tools || true
  cd ${GOPATH}/src/github.com/kubernetes-sigs/cri-tools
  git checkout tags/v1.11.0
  make
  sudo -n -E make install

  # Install gvisor-containerd-shim.
  local latest=/tmp/gvisor-containerd-shim-latest
  local shim_path=/tmp/gvisor-containerd-shim
  wget --no-verbose https://storage.googleapis.com/cri-containerd-staging/gvisor-containerd-shim/latest -O ${latest}
  wget --no-verbose https://storage.googleapis.com/cri-containerd-staging/gvisor-containerd-shim/$(cat ${latest}) -O ${shim_path}
  chmod +x ${shim_path}
  sudo -n -E mv ${shim_path} /usr/local/bin

  # Configure containerd-shim.
  local shim_config_path=/etc/containerd
  local shim_config_tmp_path=/tmp/gvisor-containerd-shim.toml
  sudo -n -E mkdir -p ${shim_config_path}
  cat > ${shim_config_tmp_path} <<-EOF
    runc_shim = "/usr/local/bin/containerd-shim"

    [runsc_config]
      debug = "true"
      debug-log = "/tmp/runsc-logs/"
      strace = "true"
      file-access = "shared"
EOF
  sudo mv ${shim_config_tmp_path} ${shim_config_path}

  # Configure CNI.
  sudo -n -E env PATH=${PATH} ${GOPATH}/src/github.com/containerd/containerd/script/setup/install-cni
}

# Run the tests that require docker.
run_docker_tests() {
  cd ${WORKSPACE_DIR}

  # These names are used to exclude tests not supported in certain
  # configuration, e.g. save/restore not supported with hostnet.
  declare -a variations=("" "-kvm" "-hostnet" "-overlay")
  for v in "${variations[@]}"; do
    # Run runsc tests with docker that are tagged manual.
    bazel test --test_output=errors --test_env=RUNSC_RUNTIME="${RUNTIME}${v}" \
      //runsc/test/image:image_test \
      //runsc/test/integration:integration_test
  done
}

# Run the tests that require root.
run_root_tests() {
  cd ${WORKSPACE_DIR}
  bazel build //runsc/test/root:root_test
  local root_test=$(find -L ./bazel-bin/ -executable -type f -name root_test | grep __main__)
  if [[ ! -f "${root_test}" ]]; then
    echo "root_test executable not found"
    exit 1
  fi
  sudo -n -E RUNSC_RUNTIME="${RUNTIME}" RUNSC_EXEC=/tmp/"${RUNTIME}"/runsc ${root_test}
}

# Find and rename all test xml and log files so that Sponge can pick them up.
# XML files must be named sponge_log.xml, and log files must be named
# sponge_log.log. We move all such files into KOKORO_ARTIFACTS_DIR, in a
# subdirectory named with the test name.
upload_test_artifacts() {
  cd ${WORKSPACE_DIR}
  for file in $(find -L "bazel-testlogs" -name "test.xml" -o -name "test.log"); do
      newpath=${KOKORO_ARTIFACTS_DIR}/$(dirname ${file})
      extension="${file##*.}"
      mkdir -p "${newpath}" && cp "${file}" "${newpath}/sponge_log.${extension}"
  done
}

# Finish runs at exit, even in the event of an error, and uploads all test
# artifacts.
finish() {
  # Grab the last exit code, we will return it.
  local exit_code=${?}
  upload_test_artifacts
  exit ${exit_code}
}

########
# MAIN #
########

main() {
  # Register finish to run at exit.
  trap finish EXIT

  # Build and run the simple tests.
  build_everything
  run_simple_tests

  # So far so good. Install more deps and run the integration tests.
  install_runtime
  install_crictl_test_deps
  run_docker_tests
  run_root_tests

  # No need to call "finish" here, it will happen at exit.
}

# Kick it off.
main
