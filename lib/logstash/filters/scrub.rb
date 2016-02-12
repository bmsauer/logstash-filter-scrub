# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "yaml"

# This scrub filter replaces text in a field based on an external
# dictionary file with regexs.
class LogStash::Filters::Scrub < LogStash::Filters::Base

  config_name "scrub"
  
  # The name of the logstash event field containing the value to be compared for a
  # match by the translate filter (e.g. `message`, `host`, `response_code`). 
  # 
  # If this field is an array, only the first value will be used.
  config :field, :validate => :string, :required => true
  
  # The full path of the external dictionary file. The format of the table
  # should be a standard YAML, JSON or CSV. Make sure you specify any integer-based keys
  # in quotes. For example, the YAML file should look something like this:
  # [source,ruby]
  #     "100": Continue
  #     "101": Switching Protocols
  #     merci: gracias
  #     old version: new version
  #
  # NOTE: it is an error to specify both `dictionary` and `dictionary_path`
  # NOTE: Currently supported formats are YAML, JSON and CSV, format selection is
  # based on the file extension, json for JSON, (yaml|yml) for YAML and csv for CSV.
  # NOTE: The JSON format only supports simple key/value, unnested objects. The CSV
  # format expects exactly two columns with the first serving as the original text,
  # the second column as the replacement
  config :dictionary_path, :validate => :path, :required => true

  # When using a dictionary file, this setting will indicate how frequently
  # (in seconds) logstash will check the dictionary file for updates.
  config :refresh_interval, :validate => :number, :default => 300
  

  public
  def register
    @dictionary = {}
    if @dictionary_path
      @next_refresh = Time.now + @refresh_interval
      raise_exception = true
      load_dictionary(raise_exception)
    end

    @logger.debug? and @logger.debug("#{self.class.name}: Dictionary - ", :dictionary => @dictionary)
  end # def register

  
  def filter(event)
    if @dictionary_path
      if @next_refresh < Time.now
        load_dictionary
        @next_refresh = Time.now + @refresh_interval
        @logger.info("refreshing dictionary file")
      end
    end

    return unless event.include?(@field) # Skip translation in case event does not have @event field.

    begin
      #If source field is array use first value and make sure source value is string
      source = event[@field].is_a?(Array) ? event[@field].first.to_s : event[@field].to_s
      matched = false

      uuidmatch = /[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}/
      @logger.debug(source =~ uuidmatch)
      
      translation = source.gsub(Regexp.union(@dictionary.keys), @dictionary)
      @logger.debug(@dictionary.to_s)
      @logger.debug(source + " " + translation)
      if source != translation
        event[@field] = translation.force_encoding(Encoding::UTF_8)
        matched = true
      end
      

      if matched
        filter_matched(event)
      end
    rescue Exception => e
      @logger.error("Something went wrong when attempting to translate from dictionary", :exception => e, :field => @field, :event => event)
    end
  end # def filter

  private
  
  def load_dictionary(raise_exception=false)
    if /.y[a]?ml$/.match(@dictionary_path)
      load_yaml(raise_exception)
    else
      raise "#{self.class.name}: Dictionary #{@dictionary_path} have a non valid format"
    end
  rescue => e
    loading_exception(e, raise_exception)
  end

  def load_yaml(raise_exception=false)
    if !File.exists?(@dictionary_path)
      @logger.warn("dictionary file read failure, continuing with old dictionary", :path => @dictionary_path)
      return
    end
    merge_dictionary!(YAML.load_file(@dictionary_path), raise_exception)
  end

  def merge_dictionary!(data, raise_exception=false)
      @dictionary.merge!(data)
  end

  def loading_exception(e, raise_exception=false)
    msg = "#{self.class.name}: #{e.message} when loading dictionary file at #{@dictionary_path}"
    if raise_exception
      raise RuntimeError.new(msg)
    else
      @logger.warn("#{msg}, continuing with old dictionary", :dictionary_path => @dictionary_path)
    end
  end

  
end # class LogStash::Filters::Example
