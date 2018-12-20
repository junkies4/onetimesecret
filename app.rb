require 'sinatra'
require 'sinatra/logger'
require 'yaml'
require 'sshkey'
require 'redis'
require 'json'
require 'pony'
require 'pp'

##############################
# Initialize
# Read app config files etc

# begin sinatra configure block
configure do
  # read main app config file
  $appconfig = YAML.load_file('config/config.yml')

  # enable sessions
  use Rack::Session::Pool

  # enable logging
  set :root, Dir.pwd
  set :logger_level, :debug

  # create connection to redis database
  if $appconfig['redis']['password'] == ''
    $redis = Redis.new(host: "#{$appconfig['redis']['host']}", port: $appconfig['redis']['port'])
  else
    $redis = Redis.new(host: "#{$appconfig['redis']['host']}", port: $appconfig['redis']['port'], password: "#{$appconfig['redis']['password']}")
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
    logger.info("mailserver = #{$appconfig['smtp']['address']}")
    Pony.mail({
      :from => $appconfig['smtp']['from'],
      :to => to,
      :subject => 'Secret Shared via Onetimescret',
      :body => "#{request.scheme}://#{request.host}/#{secreturi}",
      :via => :smtp,
      :via_options => {
        :address        => $appconfig['smtp']['address'],
        :port           => $appconfig['smtp']['port'],
        :enable_starttls_auto => false,
        # :user_name      => $appconfig['smtp']['username'],
        # :password       => $appconfig['smtp']['password'],
        # :authentication => :plain, # :plain, :login, :cram_md5, no auth by default
        :domain         => "herbosch.be" # the HELO domain provided by the client to the server
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
get '/' do
  if params['storesecret']
    @storedsecret = storesecret(params)
    halt erb :secretstored
  end

  comment      = params['comment'] || $appconfig['secrettype']['customsecret']['comment']
  email        = params['email']   || $appconfig['secrettype']['customsecret']['email']
  ttl          = params['ttl']     || $appconfig['redis']['secretttl']
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
get '/randomstring' do
  if params['storesecret']
    @storedsecret = storesecret(params)
    halt erb :secretstored
  end

  secretlength    = params['secretlength']    || $appconfig['secrettype']['randomstring']['secretlength']
  secretiscomplex = params['secretiscomplex'] || $appconfig['secrettype']['randomstring']['secretiscomplex']
  comment         = params['comment']         || $appconfig['secrettype']['randomstring']['comment']
  email           = params['email']           || $appconfig['secrettype']['randomstring']['email']
  ttl             = params['ttl']             || $appconfig['redis']['secretttl']

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
get '/sshkeypair' do
  if params['storesecret']
    @storedsecret = storesecret(params)
    if params['email'] != ''
      logger.info("= send an email to #{params['email']} =")
      logger.info(pp params.to_yaml)
      send_email(params['email'],params['secreturi'])
    end
    halt erb :secretstored
  end

  keytype       = params['keytype']       || $appconfig['secrettype']['sshkeypair']['keytype']
  keylength     = params['keylength']     || $appconfig['secrettype']['sshkeypair']['keylength']
  keycomment    = params['keycomment']    || $appconfig['secrettype']['sshkeypair']['keycomment']
  keypassphrase = params['keypassphrase'] || $appconfig['secrettype']['sshkeypair']['keypassphrase']
  comment       = params['comment']       || $appconfig['secrettype']['sshkeypair']['comment']
  email         = params['email']         || $appconfig['secrettype']['sshkeypair']['email']
  ttl           = params['ttl']           || $appconfig['redis']['secretttl']

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
