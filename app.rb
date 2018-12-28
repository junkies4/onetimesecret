require 'sinatra'
require 'sinatra/multi_route'
require 'sinatra/logger'
require 'yaml'
require 'sshkey'
require 'redis'
require 'json'
require 'pony'
require 'pp'
require 'dotenv/load'

##############################
# Initialize
# Read app config files etc

# begin sinatra configure block
configure do
  # read main app config file
  # $appconfig = YAML.load_file('config/config.yml')

  # populate appconfig hash via dotenv gem and .env config file
  $appconfig = Hash.new

  # Redis config
  $appconfig['redis_host']      = ENV['REDIS_HOST']      || nil
  $appconfig['redis_port']      = ENV['REDIS_PORT']      || nil
  $appconfig['redis_password']  = ENV['REDIS_PASSWORD']  || nil
  $appconfig['redis_secretttl'] = ENV['REDIS_SECRETTTL'] || nil

  # secrettypes: customsecret, randomstring, sshkeypair
  $appconfig['secrettype_randomstring_secretlength']    = ENV['SECRETTYPE_RANDOMSTRING_SECRETLENGTH']    || nil
  $appconfig['secrettype_randomstring_secretiscomplex'] = ENV['SECRETTYPE_RANDOMSTRING_SECRETISCOMPLEX'] || nil
  $appconfig['secrettype_randomstring_comment']         = ENV['SECRETTYPE_RANDOMSTRING_COMMENT']         || nil
  $appconfig['secrettype_randomstring_email']           = ENV['SECRETTYPE_RANDOMSTRING_EMAIL']           || nil

  $appconfig['secrettype_sshkeypair_keytype']       = ENV['SECRETTYPE_SSHKEYPAIR_KEYTYPE']       || nil
  $appconfig['secrettype_sshkeypair_keylength']     = ENV['SECRETTYPE_SSHKEYPAIR_KEYLENGTH']     || nil
  $appconfig['secrettype_sshkeypair_keycomment']    = ENV['SECRETTYPE_SSHKEYPAIR_KEYCOMMENT']    || nil
  $appconfig['secrettype_sshkeypair_keypassphrase'] = ENV['SECRETTYPE_SSHKEYPAIR_KEYPASSPHRASE'] || nil
  $appconfig['secrettype_sshkeypair_comment']       = ENV['SECRETTYPE_SSHKEYPAIR_COMMENT']       || nil
  $appconfig['secrettype_sshkeypair_email']         = ENV['SECRETTYPE_SSHKEYPAIR_EMAIL']         || nil

  $appconfig['secrettype_customsecret_secret']  = ENV['SECRETTYPE_CUSTOMSECRET_SECRET']  || nil
  $appconfig['secrettype_customsecret_comment'] = ENV['SECRETTYPE_CUSTOMSECRET_COMMENT'] || nil
  $appconfig['secrettype_customsecret_email']   = ENV['SECRETTYPE_CUSTOMSECRET_EMAIL']   || nil

  $appconfig['smtp_address']     = ENV['SMTP_ADDRESS']     || nil
  $appconfig['smtp_port']        = ENV['SMTP_PORT']        || nil
  $appconfig['smtp_username']    = ENV['SMTP_USERNAME']    || nil
  $appconfig['smtp_password']    = ENV['SMTP_PASSWORD']    || nil
  $appconfig['smtp_from']        = ENV['SMTP_FROM']        || nil
  $appconfig['smtp_helo_domain'] = ENV['SMTP_HELO_DOMAIN'] || nil

  # webrick listen everywhere
  set :bind, '0.0.0.0'
  :show_exceptions

  # enable sessions
  use Rack::Session::Pool

  # enable logging
  set :root, Dir.pwd
  set :logger_level, :debug

  # create connection to redis database
  # if $appconfig['redis_password'] == ''
  if $appconfig['redis_password'].nil?
    $redis = Redis.new(host: "#{$appconfig['redis_host']}", port: $appconfig['redis_port'])
  else
    $redis = Redis.new(host: "#{$appconfig['redis_host']}", port: $appconfig['redis_port'], password: "#{$appconfig['redis_password']}")
  end
end

############################
# Start Function Definitions
#

# begin sinatra helpers block
helpers do
  def generate_randomstring(secretlength,secretiscomplex)
    charset = Array('A'..'Z') + Array('a'..'z') + Array('0'..'9')
  
    if secretiscomplex == "true"
      charset = charset + %w{! @ # $ % ^ & * ( ) _ - + = { } [ ] ; : ? / > < , . ~}
    end
  
    CGI.escapeHTML(Array.new(secretlength) { charset.sample }.join)
  end
  
  def generate_sshkeypair(keytype,keylength,keycomment,keypassphrase)
    if keypassphrase != ''
      @sshkey = SSHKey.generate(
        bits:       keylength,
        type:       keytype,
        passphrase: keypassphrase,
        comment:    keycomment
      )
    else
      @sshkey = SSHKey.generate(
        bits:       keylength,
        type:       keytype,
        comment:    keycomment
      )
    end
  end
  
  def generate_secret(params)
    secret = Hash.new
    secret['type']            = params[:type]
    secret['comment']         = params[:comment]
    secret['email']           = params[:email]
    secret['ttl']             = params[:ttl]
  
    secret['secretlength']    = params[:secretlength]
    secret['secretiscomplex'] = params[:secretiscomplex]
  
    secret['keytype']         = params[:keytype]
    secret['keylength']       = params[:keylength]
    secret['keycomment']      = params[:keycomment]
    secret['keypassphrase']   = params[:keypassphrase]
  
    case secret['type']
    when "customsecret"
      secret['customsecret'] = params[:customsecret]
    when "randomstring"
      secret['randomstring'] = generate_randomstring(secret['secretlength'],secret['secretiscomplex'])
    when "sshkeypair"
      @sshkeypair = generate_sshkeypair(secret['keytype'],secret['keylength'],secret['keycomment'],secret['keypassphrase'])
      secret['public_key'] = @sshkeypair.public_key
      secret['ssh_public_key'] = @sshkeypair.ssh_public_key
      secret['private_key'] = @sshkeypair.private_key
      secret['encrypted_private_key'] = @sshkeypair.encrypted_private_key if secret['keypassphrase'] != ''
    end
  
    return secret
  end
  
  def storesecret ( params )
    params.delete('storesecret')
    params['secreturi'] = generate_randomstring(32,'false')
    $redis.setex "secrets:#{params['secreturi']}", params['ttl'], params
    return params
  end

  def send_email(to,secreturi)
    logger.info("mailserver = #{$appconfig['smtp_address']}")
    Pony.mail({
      :from => $appconfig['smtp_from'],
      :to => to,
      :subject => 'Secret Shared via Onetimescret',
      :body => "#{request.scheme}://#{request.host}/#{secreturi}",
      :via => :smtp,
      :via_options => {
        :address              => $appconfig['smtp_address'],
        :port                 => $appconfig['smtp_port'],
        :domain               => $appconfig['smtp_helo_domain'],
        :enable_starttls_auto => true,
        # :user_name      => $appconfig['smtp_username'],
        # :password       => $appconfig['smtp_password'],
        # :authentication => :plain, # :plain, :login, :cram_md5, no auth by default
      }
    })
  end
end

#
# End function definitions
##########################

#######################
# Start URI Definitions
#

# generate custom secret
# get '/' do
route :get, :post, '/' do
  if params['storesecret']
    @storedsecret = storesecret(params)
    halt erb :secretstored
  end

  comment      = params['comment'] || $appconfig['secrettype_customsecret_comment']
  email        = params['email']   || $appconfig['secrettype_customsecret_email']
  ttl          = params['ttl']     || $appconfig['redis_secretttl']
  customsecret = params['customsecret']

  @secret = generate_secret(
              :type         => 'customsecret',
              :comment      => comment,
              :email        => email,
              :customsecret => customsecret,
              :ttl          => ttl
            )

  erb :customsecret
end

# generate randomstring
# get '/randomstring' do
route :get, :post, '/randomstring' do
  if params['storesecret']
    @storedsecret = storesecret(params)
    halt erb :secretstored
  end

  secretlength    = params['secretlength']    || $appconfig['secrettype_randomstring_secretlength']
  secretiscomplex = params['secretiscomplex'] || $appconfig['secrettype_randomstring_secretiscomplex']
  comment         = params['comment']         || $appconfig['secrettype_randomstring_comment']
  email           = params['email']           || $appconfig['secrettype_randomstring_email']
  ttl             = params['ttl']             || $appconfig['redis_secretttl']

  @secret = generate_secret(
              :type            => 'randomstring',
              :secretlength    => secretlength.to_i,
              :secretiscomplex => secretiscomplex,
              :comment         => comment,
              :email           => email,
              :ttl             => ttl
            )

  erb :randomstring
end

# generate ssh keypair
# get '/sshkeypair' do
route :get, :post, '/sshkeypair' do
  if params['storesecret']
    @storedsecret = storesecret(params)
    if params['email'] != ''
      logger.info("= send an email to #{params['email']} =")
      logger.info(pp params.to_yaml)
      send_email(params['email'],params['secreturi'])
    end
    halt erb :secretstored
  end

  keytype       = params['keytype']       || $appconfig['secrettype_sshkeypair_keytype']
  keylength     = params['keylength']     || $appconfig['secrettype_sshkeypair_keylength']
  keycomment    = params['keycomment']    || $appconfig['secrettype_sshkeypair_keycomment']
  keypassphrase = params['keypassphrase'] || $appconfig['secrettype_sshkeypair_keypassphrase']
  comment       = params['comment']       || $appconfig['secrettype_sshkeypair_comment']
  email         = params['email']         || $appconfig['secrettype_sshkeypair_email']
  ttl           = params['ttl']           || $appconfig['redis_secretttl']

  @secret = generate_secret(
              :type          => 'sshkeypair',
              :keytype       => keytype,
              :keylength     => keylength.to_i,
              :keycomment    => keycomment,
              :keypassphrase => keypassphrase,
              :comment       => comment,
              :email         => email,
              :ttl           => ttl
            )

  erb :sshkeypair
end

# retrieve a secret
get '/:shortcode' do

  # get the secret from the redis database
  redis_secret = $redis.get "secrets:#{params['shortcode']}"

  # if secret not found in redis, halt with error
  if redis_secret == nil
    @error = "ERROR: Secret already retrieved, Secret Expired or Invalid Secret URI!" 
    halt erb(:layout)
  end

  # convert redis secret to ruby object
  @secret = JSON.parse(redis_secret.gsub('=>', ':'))

  # if secret does not contain email, show secret and halt
  if @secret['email'] == ''
    $redis.del "secrets:#{params[:shortcode]}"
    if params['format'] == "json" 
      json(JSON.parse(redis_secret.gsub('=>', ':')))
    else
      halt erb(:showsecret)
    end
  end

  # if secret contains email, ask for email input
  if @secret['email'] != '' and not params['confirmemail']
    halt erb(:confirmemail)
  end

  # if confirmation email submitted and email matches with secret email, show secret
  if params['confirmemail'] and params['email'] == @secret['email']
    $redis.del "secrets:#{params[:shortcode]}"
    halt erb(:showsecret)
  else
    # else, confirmation email not correct, abort
    @error = "ERROR: Email address incorrect!" 
    halt erb(:layout)
  end

end
