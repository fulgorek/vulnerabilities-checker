#!/usr/bin/env ruby

require 'json'
require 'zlib'
require 'open-uri'
require 'net/smtp'

module Vuln
  class CVE

    attr_reader :database, :items

    # array of products to search
    PRODUCTS = %w(openssl openvpn openssh ssl)

    # Strict filter indicates search a whole word for product
    # `ssl` will match on `openssl` if strict filter is false
    STRICT_FILTER  = false

    # array of years to search for vulnerabilities
    # leave emtpy to fetch only the `recent` ones
    YEARS = [2017]

    # Include most recent(fresh) vulnerabilities
    INCLUDE_RECENT = true

    # Name of the database
    DATABASE  = 'database.lock'

    # Email configuration
    # enable/disable email. database will NOT be saved if email is DISABLED!
    SEND_EMAIL = true

    # Please fill `env.sh.sample` rename it to `.env.sh` and source it
    # before in order to prevent credentials leaking
    SMTP = {
      :from    => 'from@hotmail.com',
      :to      => 'to@domain.com',
      :host    => 'smtp.live.com',
      :port    => 25,
      :ssl     => true
    }

    # Endpoints for the API calls
    ENDPOINTS = {
      :meta     => 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%s.meta',
      :database => 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%s.json.gz',
      :details  => 'http://www.cvedetails.com/cve/%s'
    }

    # END OF CONFIGURATION

    def initialize
      YEARS.sort.each {|year| bootstrap(year)}
      bootstrap('recent') if INCLUDE_RECENT == true
      prepare_items
      send_email
      lock_database
    end

    private

    def bootstrap(version)
      verify_version(version)
      fetch_database(version)
      filter_vulnerable
      filter_saved
      filter_products
    end

    def verify_version(version)
      if !(YEARS.map{|x| x.to_s} << 'recent').include?(version.to_s)
        puts "Invalid database version. Aborting!"
        exit
      end
    end

    def fetch_database(version)
      data      = fetch(sprintf(ENDPOINTS[:database], version))
      gz        = Zlib::GzipReader.new(data)
      items     = JSON.parse(gz.read)['CVE_Items']
      (@database ||= []).push(*items)
    end

    def fetch(url)
      open(URI.parse(url))
      rescue
        puts "HTTP Request failed. Aborting!"
        exit
    end

    def filter_vulnerable
      database.delete_if do |item|
        item['CVE_configurations']['CVE_configuration_data'].empty?
      end
    end

    def filter_saved
      if ::File.file?("#{DATABASE}") and saved_database.any?
        database.delete_if do |item|
          saved_database.include?(item['CVE_data_meta']['CVE_ID'])
        end
      end
    end

    def filter_products
      re = Regexp.union(PRODUCTS.map{ |s| Regexp.new("#{strict_filter}#{s}", Regexp::IGNORECASE) })
      database.delete_if do |item|
        item['CVE_affects']['CVE_vendor']['CVE_vendor_data'].map{|v| v['CVE_vendor_name']}.select do |e|
          e.match(re)
        end.empty?
      end
    end

    def strict_filter
      STRICT_FILTER == true ? '^' : ''
    end

    def serialize_vulnerabilities
      items.map{|item| item[1].map{|v| v[0]}}.flatten
    end

    def lock_database
      save_database(serialize_vulnerabilities) if items.any?
    end

    def save_database(items)
      ::File.open("#{DATABASE}", 'w') {|f| f.write(::Marshal.dump(items))}
    end

    def saved_database
      @saved_database ||= ::Marshal.load(::File.read("#{DATABASE}"))
    end

    def prepare_items
      bootstrap('recent') if @database.nil?
      @items ||= {}
      database.each do |u|
        kind    = u['CVE_affects']['CVE_vendor']['CVE_vendor_data'].map{|v| v['CVE_vendor_name']}.join('/')
        id      = u['CVE_data_meta']['CVE_ID']
        desc    = u['CVE_description']['CVE_description_data'].first['value']
        details = sprintf(ENDPOINTS[:details], id)
        (items[kind] ||= []).push([id, desc, details])
      end
      items
    end

    def send_email?
      if !items.any?
        puts "No vulnerabilities found... yet!"
        exit
      elsif SEND_EMAIL == false
        exit
      elsif ENV['EMAIL_PASSWORD'].nil?
        puts "Missing credentials on your environment..."
        exit
      end
    end

    def build_message
      message = <<MESSAGE_END
From: Vuln Robot <#{SMTP[:from]}>
To: Receipt <#{SMTP[:to]}>
Subject: New vulnerabilities found!

#{build_message_items}
MESSAGE_END
    end

    def build_message_items
      message = "#{items.size} Vulnerabilities we're found:\n\n"
      items.each do |item|
        message << "\n" + item[0]
        message << "\n-------------\n"
        message << item[1].join("\n\r")
        message << "\n-------------\n"
      end
      message
    end

    def send_email
      send_email?
      begin
        smtp = Net::SMTP.new(SMTP[:host], SMTP[:port])
        smtp.enable_starttls if SMTP[:ssl]
        smtp.start(SMTP[:host], SMTP[:from], ENV['EMAIL_PASSWORD'], :login) do
          smtp.send_message(build_message, SMTP[:from], SMTP[:to])
        end
      rescue Net::SMTPAuthenticationError, Net::SMTPServerBusy, Net::SMTPSyntaxError, Net::SMTPFatalError, Net::SMTPUnknownError => e
        puts 'Invalid Email credentials...'
      end
        puts "Email Sent with #{items.size} vulnerabilities found!"
    end
  end
end

# run baby
Vuln::CVE.new
