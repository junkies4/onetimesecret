require 'sinatra'
require 'sinatra/multi_route'
require 'sinatra/logger'
require 'yaml'
require 'sshkey'
require 'redis'
require 'json'
require 'pony'
require 'dotenv/load'
require 'openssl'
require 'pp'
require 'statsd-ruby'
include ERB::Util

##############################
# Initialize
# Read app config files etc

# begin sinatra configure block
configure do
  # bind
  set :bind, '0.0.0.0'

  # populate appconfig hash via environment vars or read from the .env config file
  $appconfig = Hash.new

  # Base URL
  $appconfig['base_url']        = ENV['BASE_URL'] || nil

  # Application Name
  $appconfig['app_name']        = ENV['APP_NAME'] || nil

  # HTML email logo
  $appconfig['html_email_logo'] = ENV['HTML_EMAIL_LOGO'] || nil

  # Statsd config
  $appconfig['statsd_host']     = ENV['STATSD_HOST']     || nil
  $appconfig['statsd_port']     = ENV['STATSD_PORT']     || nil

  # Redis config
  $appconfig['redis_host']      = ENV['REDIS_HOST']      || nil
  $appconfig['redis_port']      = ENV['REDIS_PORT']      || nil
  $appconfig['redis_password']  = ENV['REDIS_PASSWORD']  || nil
  $appconfig['redis_secretttl'] = ENV['REDIS_SECRETTTL'] || nil

  $appconfig['encryption_key']  = ENV['ENCRYPTION_KEY']  || nil
  $appconfig['encryption_auth'] = ENV['ENCRYPTION_AUTH']  || nil

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

  # SMTP config
  $appconfig['smtp_address']     = ENV['SMTP_ADDRESS']     || nil
  $appconfig['smtp_port']        = ENV['SMTP_PORT']        || nil
  $appconfig['smtp_username']    = ENV['SMTP_USERNAME']    || nil
  $appconfig['smtp_password']    = ENV['SMTP_PASSWORD']    || nil
  $appconfig['smtp_from']        = ENV['SMTP_FROM']        || nil
  $appconfig['smtp_helo_domain'] = ENV['SMTP_HELO_DOMAIN'] || nil

  # enable sessions
  use Rack::Session::Pool

  # enable logging
  set :root, Dir.pwd
  set :logger, Logger.new(STDERR)

  # create connection to redis database
  if $appconfig['redis_password'].nil?
    $redis = Redis.new(host: "#{$appconfig['redis_host']}", port: $appconfig['redis_port'])
  else
    $redis = Redis.new(host: "#{$appconfig['redis_host']}", port: $appconfig['redis_port'], password: "#{$appconfig['redis_password']}")
  end

  # create connection to statsd metrics backend
  unless $appconfig['statsd_host'].nil?
    $statsd = Statsd.new("#{$appconfig['statsd_host']}",$appconfig['statsd_port'])
  end
end

############################
# Start Function Definitions
#

# begin sinatra helpers block
helpers do

  def redirect_to_base_url()
    accessed_url = "#{request.scheme}://#{request.host}"

    if accessed_url != $appconfig['base_url'] and not $appconfig['base_url'].nil?
      redirect to ($appconfig['base_url'] + "#{request.path}"), 301
    end
  end

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

  # encrypt a string using a pre-defined encryption key and encryption_auth
  def encrypt(unencrypted_text,encryption_key,encryption_auth)

    # initialize new cipher object
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt

    # generate random Initialization Vector (iv) aka Salt
    # the iv will be returned together with the encrypted string because it is required when decrypting
    iv = cipher.random_iv
    encrypted_iv = Base64.encode64(iv)

    # set the predefined encryption_key as the cipher.key
    cipher.key = encryption_key

    # set the predefined encryption_auth as the cipher.auth_data
    cipher.auth_data = encryption_auth

    # encrypt the string and Base64 encode it
    encrypted_text = Base64.encode64(cipher.update(unencrypted_text) + cipher.final)

    # get the authentication tag
    auth_tag = Base64.encode64(cipher.auth_tag)

    # create new hash to store the IV, auth_tag and encrypted string
    encrypted_result             = Hash.new
    encrypted_result['params']   = encrypted_text
    encrypted_result['iv']       = encrypted_iv
    encrypted_result['auth_tag'] = auth_tag

    return encrypted_result
  end

  # decrypt a string using a pre-defined encryption key and encryption_auth
  def decrypt(encrypted_secret,encryption_key,encryption_auth)

    # initialize new cipher object
    decipher = OpenSSL::Cipher.new('aes-256-gcm')
    decipher.decrypt

    # use the base64 decoded IV which was fetched from the redis secret
    decipher.iv = Base64.decode64(encrypted_secret['iv'])

    # set the predefined encryption_key as the decipher.key
    decipher.key = encryption_key

    # set the predefined encryption_auth as the decipher.auth_data
    decipher.auth_data = encryption_auth

    # use the base64 decoded authentication tag which was fetched from the redis secret
    decipher.auth_tag = Base64.decode64(encrypted_secret['auth_tag'])

    # decrypt and decode the secret
    decrypted_secret = Base64.decode64(decipher.update(Base64.decode64(encrypted_secret['params'])) + decipher.final)

    # pass the plaintext data back to the application
    return decrypted_secret
  end

  def storesecret(params)
    params.delete('storesecret')
    params['secreturi'] = generate_randomstring(32,'false')

    # encrypt all parameter values before storing them:
    # convert the params hash to json and then Base64 encode it.
    # the 'encrypt' function returns a hash containing the Base64 encode encrypted string and iv.
    encrypted_params = Hash.new
    encrypted_params = encrypt(Base64.encode64(JSON.dump(params)),$appconfig['encryption_key'],$appconfig['encryption_auth'])

    # store the hash in redis
    $redis.setex "secrets:#{params['secreturi']}", params['ttl'], encrypted_params

    # and send out a metric of this event
    update_metrics("secretscreated") unless $statsd.nil?

    return params
  end

  def update_metrics(metricname)
    # the value of #{metricname} can be 'secretscreated' or 'secretsretrieved'
    # this value is used as the metric name sent to statsd

    if metricname == "secretscreated" || "secretsretrieved" || "secretsinvalid"
      # Increment a counter with 1 to record when a secret is created or retrieved
      $statsd.increment("statsd.OnetimeSecret.#{metricname}")

      # Each time a record is created or removed,
      # read the number of records in the redis database and store this value
      $statsd.gauge("statsd.OnetimeSecret.secretsindbase",$redis.dbsize)
    else
      @error = "update_metrics() metricname must be 'secretscreated', 'secretsretrieved' or 'secretsinvalid'"
      halt erb(:layout)
    end

    return
  end

  def send_email(to,secreturi)
    context = binding
    html_body = ERB.new(File.read("views/email-html-template.erb")).result(context)
    text_body = ERB.new(File.read("views/email-text-template.erb")).result(context)

    Pony.mail({
      :from        => $appconfig['smtp_from'],
      :to          => to,
      :subject     => 'Secret shared via Onetimescret',
      :body        => text_body,
      :html_body   => html_body,
      :via         => :smtp,
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

    logger.info "mail sent to #{to}"
  end
end

#
# End function definitions
##########################

#######################
# Start URI Definitions
#

# help
route :get, '/help' do
  redirect_to_base_url()

  erb :help
end

# generate custom secret
route :get, :post, '/' do
  redirect_to_base_url()

  if params['storesecret']
    @storedsecret = storesecret(params)
    if params['email'] != ''
      send_email(params['email'],params['secreturi'])
    end
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
route :get, :post, '/randomstring' do
  redirect_to_base_url()

  if params['storesecret']
    @storedsecret = storesecret(params)
    if params['email'] != ''
      send_email(params['email'],params['secreturi'])
    end
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
route :get, :post, '/sshkeypair' do
  redirect_to_base_url()

  if params['storesecret']
    @storedsecret = storesecret(params)
    if params['email'] != ''
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
route :get, :post, '/:shortcode' do
  redirect_to_base_url()

  # get the secret from the redis database
  redis_secret = $redis.get "secrets:#{params['shortcode']}"

  # if secret not found in redis, halt with error
  if redis_secret == nil
    @error = "ERROR: Secret already retrieved, Secret Expired or Invalid Secret URI!" 
    update_metrics("secretsinvalid") unless $statsd.nil?
    halt erb(:layout)
  end

  if params['revealsecret']
    # template 'showsecret' needs this variable so it knows it can reveal the secret
    @revealsecret = true

    # convert redis secret to ruby object
    # this redis hash contains a base64 encoded salt and the encrypted secret, also base64 encoded
    encrypted_secret = JSON.parse(redis_secret.gsub('=>', ':'))

    # decode and decrypt the secret
    @secret = JSON.parse(decrypt(encrypted_secret,$appconfig['encryption_key'],$appconfig['encryption_auth']))

    # if the secret does not contain email, show secret and halt
    if @secret['email'] == ''
      $redis.del "secrets:#{params[:shortcode]}"
      update_metrics("secretsretrieved") unless $statsd.nil?
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
    if params['confirmemail'] and params['email'].downcase == @secret['email'].downcase
      $redis.del "secrets:#{params[:shortcode]}"
      update_metrics("secretsretrieved") unless $statsd.nil?
      halt erb(:showsecret)
    else
      # else, confirmation email not correct, abort
      @error = "ERROR: Email address incorrect!" 
      halt erb(:layout)
    end
  else
    # if #{revealsecret} is false, display a reveal button, not the secret
    @shortcode = params['shortcode']
    halt erb(:showsecret)
  end
end
