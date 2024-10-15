FROM ruby:3.3.5
WORKDIR /app
COPY ./src /app
RUN bundle install
EXPOSE 4567
CMD ["ruby","app.rb"]
