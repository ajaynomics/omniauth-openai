# frozen_string_literal: true

require "test_helper"

class KeySetTest < Minitest::Test
  def setup
    @time = 0
    @downloads = 0
    @key_set = OmniAuth::OpenAI::KeySet.new(ttl: 3600, refresh_interval: 300, clock: -> { @time })
  end

  def test_downloads_once_and_reuses_the_keys
    2.times { fetch }

    assert_equal 1, @downloads
  end

  def test_downloads_again_once_the_keys_expire
    fetch
    @time = 3600
    fetch

    assert_equal 2, @downloads
  end

  def test_an_unknown_key_forces_a_download_once_per_interval
    fetch
    @time = 299
    fetch(kid_not_found: true)
    assert_equal 1, @downloads

    @time = 300
    fetch(kid_not_found: true)
    assert_equal 2, @downloads
  end

  private

  def fetch(kid_not_found: false)
    @key_set.fetch(kid_not_found: kid_not_found) { { "keys" => [ @downloads += 1 ] } }
  end
end
