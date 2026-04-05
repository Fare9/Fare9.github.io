FROM ruby:3.2-alpine

RUN apk add --no-cache \
    build-base \
    git \
    nodejs

WORKDIR /site

COPY Gemfile Gemfile.lock ./
RUN bundle install

COPY . .

EXPOSE 4000 35729

CMD ["bundle", "exec", "jekyll", "serve", \
     "--host", "0.0.0.0", \
     "--livereload", \
     "--incremental"]
