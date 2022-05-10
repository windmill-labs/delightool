FROM mhart/alpine-node:14 as frontend

# install dependencies
WORKDIR /frontend
COPY ./frontend/package.json ./frontend/package-lock.json ./
RUN npm ci

# Copy all local files into the image.
COPY frontend .
RUN mkdir /backend
COPY /backend/openapi.yaml /backend/openapi.yaml
RUN npm run generate-backend-client
RUN npm run build

FROM rust:slim-buster as builder

RUN apt-get update && apt-get install -y git libssl-dev pkg-config

RUN USER=root cargo new --bin delightool
WORKDIR /delightool

COPY ./backend/Cargo.toml .
COPY ./backend/Cargo.lock .
COPY ./backend/.cargo/ .cargo/

ENV CARGO_INCREMENTAL=1

RUN cargo build --release
RUN rm src/*.rs

ADD ./backend ./
ADD Pipfile ../.

RUN rm ./target/release/deps/delightool*
ENV SQLX_OFFLINE=true

COPY --from=0 /frontend /frontend

ADD .git/ .git/
RUN cargo build --release


FROM debian:buster-slim
ARG APP=/usr/src/app

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata libpq5 python3 python3-pip\
    make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev mecab-ipadic-utf8 git\
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pipenv

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -m -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

USER $APP_USER

ENV PYTHON_VERSION 3.10.1
ENV PYENV_ROOT /home/${APP_USER}/.pyenv
ENV PATH $PYENV_ROOT/shims:$PYENV_ROOT/bin:$PATH

RUN set -ex \
    && curl https://pyenv.run | bash \
    && pyenv update \
    && pyenv install $PYTHON_VERSION \
    && pyenv global $PYTHON_VERSION \
    && pyenv rehash


COPY --from=builder /delightool/target/release/delightool ${APP}/delightool

USER root
RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER


WORKDIR ${APP}
EXPOSE 8000

CMD ["./delightool"]
