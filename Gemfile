# frozen_string_literal: true

source "https://rubygems.org"

gemspec

# CI runs the suite against both supported ruby-jwt majors.
gem "jwt", ENV["JWT_VERSION"] if ENV["JWT_VERSION"]
