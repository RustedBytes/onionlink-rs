FROM quay.io/pypa/manylinux_2_28_x86_64 AS build

ARG PYTHON_TAGS="cp38-cp38 cp39-cp39 cp310-cp310 cp311-cp311 cp312-cp312 cp313-cp313 cp313-cp313t cp314-cp314 cp314-cp314t"
ARG RUST_TOOLCHAIN=stable

ENV PATH=/root/.cargo/bin:${PATH}

RUN dnf install -y curl gcc pkgconf-pkg-config \
    && dnf clean all \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"

WORKDIR /src
COPY . .

RUN mkdir -p /wheelhouse \
    && for tag in ${PYTHON_TAGS}; do \
        python="/opt/python/${tag}/bin/python"; \
        maturin="/opt/python/${tag}/bin/maturin"; \
        "${python}" -m pip install --upgrade pip maturin; \
        "${maturin}" build --release \
            --locked \
            --manifest-path crates/onionlink-py/Cargo.toml \
            --interpreter "${python}" \
            --compatibility manylinux_2_28 \
            --out /wheelhouse; \
      done

FROM scratch AS wheels
COPY --from=build /wheelhouse /
