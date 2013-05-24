<?php

/**
 * @file
 *   Proxy between any request and Acquia's hosted solr search service.
 *
 *   This file and settings-search-proxy.php should be placed in the same
 *   directory as the acquia_search module.
 *
 *   The main trick to using it is that you need to get the derived key to
 *   put in the settings file - If you put the search proxy into your
 *   docroot, it will email you the necessary information.
 *
 *   Once installed you can, for example, do a search directly against your
 *   Solr index like:
 *
 *   http://127.0.0.1:8082/1.x-6.x-dev/search-proxy.php/select?q=drupal
 *
 */

// Development defines
define("ACQUIA_DEVELOPMENT_NOSSL", TRUE);
define("VERBOSE", TRUE);

// Define the version of this script.
define('ACQUIA_SEARCH_PROXY_VERSION', "1.0");

$default_settings = array(
  'node_access' => TRUE,
  'allowed_ip' => array(
    '127.0.0.1',
  ),
  'host' => 'search.acquia.com',
  'derived_key_salt' => '',
);

$settings = array();

// This allows the use of symlinks.
$dirname = dirname($_SERVER['SCRIPT_FILENAME']);

/**
 * settings-search-proxy.php defines the site- and subscription-specific
 * options for this script.
 */
include $dirname . '/settings-search-proxy.php';

// Merge in defaults.
$settings = $settings + $default_settings;

if (isset($_SERVER['REMOTE_ADDR']) && !in_array($_SERVER['REMOTE_ADDR'], $settings['allowed_ip'])) {
  header('HTTP/1.0 403 Access Denied.');
  echo 'Access Denied.' . "\n";
  exit;
}

if (empty($settings['acquia_identifier']) || (empty($settings['acquia_key']) && empty($settings['derived_key']))) {
  header('HTTP/1.0 403 Invalid credentials.');
  echo 'Invalid credentials.' . "\n";
  exit;
}

/**
 * acquia_search.module defines functions:
 *
 * acquia_search_auth_cookie(&$url, $string = '', $derived_key = NULL)
 * acquia_search_authenticator($string, $nonce, $derived_key = NULL)
 * acquia_search_valid_response($hmac, $nonce, $string, $derived_key = NULL)
 * acquia_search_extract_hmac($http_response_header)
 * _acquia_search_hmac($key, $string)
 */

/**
 * Modify a solr base url and construct a hmac authenticator cookie.
 *
 * @param $url
 *  The solr url beng requested - passed by reference and may be altered.
 * @param $string
 *  A string - the data to be authenticated, or empty to just use the path
 *  and query from the url to build the authenticator.
 * @param $derived_key
 *  Optional string to supply the derived key.
 *
 * @return
 *  An array containing the string to be added as the content of the
 *  Cookie header to the request and the nonce.
 */
function acquia_search_auth_cookie(&$url, $string = '', $derived_key = NULL) {
  $uri = parse_url($url);

  // Add a scheme - should always be https if available.
  if (in_array('ssl', stream_get_transports(), TRUE) && !defined('ACQUIA_DEVELOPMENT_NOSSL')) {
    $scheme = 'https://';
    $port = '';
  }
  else {
    $scheme = 'http://';
    $port = (isset($uri['port']) && $uri['port'] != 80) ? ':'. $uri['port'] : '';
  }
  $path = isset($uri['path']) ? $uri['path'] : '/';
  $query = isset($uri['query']) ? '?'. $uri['query'] : '';
  $url = $scheme . $uri['host'] . $port . $path . $query;

  // 32 character nonce.
  $nonce = base64_encode(drupal_random_bytes(24));

  if ($string) {
    $auth_header = acquia_search_authenticator($string, $nonce, $derived_key);
  }
  else {
    $auth_header = acquia_search_authenticator($path . $query, $nonce, $derived_key);
  }
  return array($auth_header, $nonce);
}

/**
 * Creates an authenticator based on a data string and HMAC-SHA1.
 */
function acquia_search_authenticator($string, $nonce, $derived_key = NULL) {
  if (empty($derived_key)) {
    $derived_key = _acquia_search_derived_key();
  }
  if (empty($derived_key)) {
    // Expired or invalid subscription - don't continue.
    return '';
  }
  else {
    $time = time();
    return 'acquia_solr_time='. $time .'; acquia_solr_nonce='. $nonce .'; acquia_solr_hmac='. _acquia_search_hmac($derived_key, $time . $nonce . $string) .';';
  }
}

/**
 * Validate the authenticity of returned data using a nonce and HMAC-SHA1.
 *
 * @return
 *  TRUE or FALSE.
 */
function acquia_search_valid_response($hmac, $nonce, $string, $derived_key = NULL) {
  if (empty($derived_key)) {
    $derived_key = _acquia_search_derived_key();
  }
  return $hmac == _acquia_search_hmac($derived_key, $nonce . $string);
}

/**
 * Look in the headers and get the hmac_digest out
 * @return string hmac_digest
 *
 */
function acquia_search_extract_hmac($http_response_header) {
  $reg = array();
  if (is_array($http_response_header)) {
    foreach ($http_response_header as $header) {
      if (preg_match("/Pragma:.*hmac_digest=(.+);/i", $header, $reg)) {
        return trim($reg[1]);
      }
    }
  }
  return '';
}

/**
 * Calculates a HMAC-SHA1 of a data string.
 *
 * See RFC2104 (http://www.ietf.org/rfc/rfc2104.txt). Note, the result of this
 * must be identical to using hash_hmac('sha1', $string, $key);  We don't use
 * that function since PHP can be missing it if it was compiled with the
 * --disable-hash switch. However, the hash extension is enabled by default
 * as of PHP 5.1.2, so we should consider requiring it and using the built-in
 * function since it is a little faster (~1.5x).
 */
function _acquia_search_hmac($key, $string) {
  return hash_hmac('sha1', $string, $key);
}

function add_request_id(&$url) {
  $id = uniqid();
  if (!stristr($url,'?')) {
    $url .= "?";
  }
  $url .= '&request_id=' . $id;
  return $id;
}

/**
 * Get subscription status from the Acquia Network, and store the result.
 *
 * This check also sends a heartbeat to the Acquia Network unless
 * $params['no_heartbeat'] == 1.
 */
function acquia_agent_check_subscription($params = array()) {
  // Default return value is FALSE.
  $subscription = FALSE;
  if (!empty($settings['acquia_identifier']) && !empty($settings['acquia_key'])) {
    $data = acquia_agent_call('acquia.agent.subscription', $params);
    $subscription['timestamp'] = time();
    if ($errno = xmlrpc_errno()) {
      switch ($errno) {
        case SUBSCRIPTION_NOT_FOUND:
        case SUBSCRIPTION_EXPIRED:
          variable_del('acquia_subscription_data');
          break;
      }
    }
    elseif (acquia_agent_valid_response($data)) {
      $subscription += $data['result']['body'];
      variable_set('acquia_subscription_data', $subscription);
      // use: acquia_agent_settings('acquia_subscription_data');
    }
    else {
      watchdog('acquia agent', 'HMAC validation error: <pre>@data</pre>', array('@data' => print_r($data, TRUE)), WATCHDOG_ERROR);
    }
  }
  return $subscription;
} 

/**
 * Derive a key for the solr hmac using the information shared with acquia.com.
 */
function _acquia_search_derived_key() {
  global $settings;
  static $derived_key = NULL;
  if (!isset($derived_key)) {
    $derivation_string = $settings['acquia_identifier'] . 'solr' . $settings['derived_key_salt'];
    $derived_key = _acquia_search_hmac($settings['acquia_key'], str_pad($derivation_string, 80, $derivation_string));
  }
  return $derived_key;
}

/**
 * Perform an HTTP request.  This function is copied and modified
 * from Drupal 6's common.inc.
 *
 * @param $context
 *   A PHP stream context created with stream_create_context().  This
 *   context will be used when a socket connection is created.
 * @param ...
 *   The rest of the parameters and return values are the same as xmlrpc().
 */
function http_request($url, $headers = array(), $method = 'GET', $data = NULL, $retry = 3) {
  $result = new stdClass();

  // Parse the URL and make sure we can handle the schema.
  $uri = parse_url($url);

  switch ($uri['scheme']) {
    case 'http':
      $port = isset($uri['port']) ? $uri['port'] : 80;
      $host = $uri['host'] . ($port != 80 ? ':'. $port : '');
      $fp = @fsockopen($uri['host'], $port, $errno, $errstr, 15);
      break;
    case 'https':
      // Note: Only works for PHP 4.3 compiled with OpenSSL.
      $port = isset($uri['port']) ? $uri['port'] : 443;
      $host = $uri['host'] . ($port != 443 ? ':'. $port : '');
      $fp = @fsockopen('ssl://'. $uri['host'], $port, $errno, $errstr, 20);
      break;
    default:
      break;
  }

  // Make sure the socket opened properly.
  if (!$fp) {
    $result->raw_headers[] = "HTTP/1.0 500 Internal Server Error";
    $result->code = 500;
    return $result;
  }

  // Construct the path to act on.
  $path = isset($uri['path']) ? $uri['path'] : '/';
  if (isset($uri['query'])) {
    $path .= '?'. $uri['query'];
  }

  // Create HTTP request.
  $defaults = array(
    // RFC 2616: "non-standard ports MUST, default ports MAY be included".
    // We don't add the port to prevent from breaking rewrite rules checking the
    // host that do not take into account the port number.
    'Host' => "Host: $host",
  );

  // Only add Content-Length if we actually have any content or if it is a POST
  // or PUT request. Some non-standard servers get confused by Content-Length in
  // at least HEAD/GET requests, and Squid always requires Content-Length in
  // POST/PUT requests.
  if (!empty($data) || $method == 'POST' || $method == 'PUT') {
    $defaults['Content-Length'] = 'Content-Length: '. strlen($data);
  }

  // If the server url has a user then attempt to use basic authentication
  if (isset($uri['user'])) {
    $defaults['Authorization'] = 'Authorization: Basic '. base64_encode($uri['user'] . (!empty($uri['pass']) ? ":". $uri['pass'] : ''));
  }

  foreach ($headers as $header => $value) {
    $defaults[$header] = $header .': '. $value;
  }

  $request = $method .' '. $path ." HTTP/1.0\r\n";
  $request .= implode("\r\n", $defaults);
  $request .= "\r\n\r\n";
  if ($data) {
    $request .= $data ."\r\n";
  }
  $result->request = $request;

  fwrite($fp, $request);

  // Fetch response.
  $response = '';
  while (!feof($fp) && $chunk = fread($fp, 1024)) {
    $response .= $chunk;
  }
  fclose($fp);

  // Parse response.
  list($split, $result->data) = explode("\r\n\r\n", $response, 2);
  $split = preg_split("/\r\n|\n|\r/", $split);

  $result->headers = array();
  $result->raw_headers = array();
  $line = array_shift($split);
  list($protocol, $code, $text) = explode(' ', trim($line), 3);
  // We must force a HTTP/1.0 response to avoid problems with chunked encoding.
  $result->raw_headers[] = "HTTP/1.0 $code $text";

  // Parse headers.
  while ($line = trim(array_shift($split))) {
    list($header, $value) = explode(':', $line, 2);
    $result->raw_headers[] = $line;
    $result->headers[$header] = trim($value);
  }

  switch ($code) {
    case 301: // Moved permanently
    case 302: // Moved temporarily
    case 307: // Moved temporarily
      $location = $result->headers['Location'];
      if ($retry) {
        $result = http_request($context, $result->headers['Location'], $headers, $method, $data, --$retry);
        $result->redirect_code = $result->code;
      }
      $result->redirect_url = $location;
      break;
  }

  $result->code = $code;
  return $result;
}


/**
 * Returns a string of highly randomized bytes (over the full 8-bit range).
 *
 * This function is better than simply calling mt_rand) or any other built-in
 * PHP function because it can return a long string of bytes (compared to < 4
 * bytes normally from mt_rand)) and uses the best available pseudo-random source.
 *
 * @param $count
 *   The number of characters (bytes) to return in the string.
 */
function drupal_random_bytes($count) {
  // $random_state does not use drupal_static as it stores random bytes.
  static $random_state, $bytes, $php_compatible;
  // Initialize on the first call. The contents of $_SERVER includes a mix of
  // user-specific and system information that varies a little with each page.
  if (!isset($random_state)) {
    $random_state = print_r($_SERVER, TRUE);
    if (function_exists('getmypid')) {
      // Further initialize with the somewhat random PHP process ID.
      $random_state .= getmypid();
    }
    $bytes = '';
  }
  if (strlen($bytes) < $count) {
    // PHP versions prior 5.3.4 experienced openssl_random_pseudo_bytes()
    // locking on Windows and rendered it unusable.
    if (!isset($php_compatible)) {
      $php_compatible = version_compare(PHP_VERSION, '5.3.4', '>=');
    }
    // /dev/urandom is available on many *nix systems and is considered the
    // best commonly available pseudo-random source.
    if ($fh = @fopen('/dev/urandom', 'rb')) {
      // PHP only performs buffered reads, so in reality it will always read
      // at least 4096 bytes. Thus, it costs nothing extra to read and store
      // that much so as to speed any additional invocations.
      $bytes .= fread($fh, max(4096, $count));
      fclose($fh);
    }
    // openssl_random_pseudo_bytes() will find entropy in a system-dependent
    // way.
    elseif ($php_compatible && function_exists('openssl_random_pseudo_bytes')) {
      $bytes .= openssl_random_pseudo_bytes($count - strlen($bytes));
    }
    // If /dev/urandom is not available or returns no bytes, this loop will
    // generate a good set of pseudo-random bytes on any system.
    // Note that it may be important that our $random_state is passed
    // through hash() prior to being rolled into $output, that the two hash()
    // invocations are different, and that the extra input into the first one -
    // the microtime() - is prepended rather than appended. This is to avoid
    // directly leaking $random_state via the $output stream, which could
    // allow for trivial prediction of further "random" numbers.
    while (strlen($bytes) < $count) {
      $random_state = hash('sha256', microtime() . mt_rand() . $random_state);
      $bytes .= hash('sha256', mt_rand() . $random_state, TRUE);
    }
  }
  $output = substr($bytes, 0, $count);
  $bytes = substr($bytes, $count);
  return $output;
}

/**
 * Verify the derived key
 */
if (empty($settings['derived_key'])) {
  $settings['derived_key'] = _acquia_search_derived_key();
  if (!empty($settings['derived_key']) && isset($_SERVER['PATH_INFO']) && $_SERVER['PATH_INFO'] == '/derived_key' && (!isset($_SERVER['SERVER_SOFTWARE']) && (php_sapi_name() == 'cli' || (is_numeric($_SERVER['argc']) && $_SERVER['argc'] > 0)))) {
    echo $settings['derived_key'] . "\n";
    exit;
  }
}


/**
 * The actual proxy functionality:
 */

$req_query = empty($_SERVER['QUERY_STRING']) ? '' : '?'. $_SERVER['QUERY_STRING'];
if ($settings['node_access']) {
  // Add filter for only content available to anonymous users.
  $req_query .= $req_query ? '&' : '?';
  $req_query .= 'fq=nodeaccess_all:0';
}
$req_path = empty($_SERVER['PATH_INFO']) ? '/' : $_SERVER['PATH_INFO'];

// TODO - better ping handling.
$ping = strpos($req_path, '/admin/ping') === 0;
// TODO - deny update path separately.

$url = 'http://'. $settings['host'] . '/solr/' . $settings['acquia_identifier'] . $req_path . $req_query;

add_request_id($url);

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] == 'POST') {
  $rawPost = @file_get_contents('php://input');
  // TODO - just throw away request headers?
  list($cookie, $nonce) = acquia_search_auth_cookie($url, $rawPost, $settings['derived_key']);
  if (empty($cookie)) {
    header('HTTP/1.0 500 Invalid authentication string.');
    exit;
  }
  $request_headers = array(
    'Content-Type' => $_SERVER['CONTENT_TYPE'],
    'Cookie' => $cookie,
    'User-Agent' => 'acquia_proxy/'. ACQUIA_SEARCH_PROXY_VERSION,
  );
  $method = 'POST';
}
else {
  $rawPost = '';
  list($cookie, $nonce) = acquia_search_auth_cookie($url, '', $settings['derived_key']);
  if (empty($cookie)) {
    header('HTTP/1.0 500 Invalid authentication string.');
    exit;
  }
  $request_headers = array(
    'Cookie' => $cookie,
    'User-Agent' => 'acquia_proxy/'. ACQUIA_SEARCH_PROXY_VERSION,
  );
  $method = 'GET';
}

if (defined('VERBOSE')) {
  echo "URL: " . $url . PHP_EOL;
  echo "Cookie: " . $cookie . PHP_EOL;
  echo "Derived Key: " . $settings['derived_key'] . PHP_EOL;
}
$result = http_request($url, $request_headers, $method, $rawPost);

if ($result->code == 200 && !$ping) {
  $hmac = acquia_search_extract_hmac($result->raw_headers);
  if (!acquia_search_valid_response($hmac, $nonce, $result->data, $settings['derived_key'])) {
    header('HTTP/1.0 500 Authentication of search content failed url: '. $url);
    exit;
  }
}

// Reproduce the headers we received, except with HTTP/1.0 forced.
foreach ($result->raw_headers as $header) {
  header($header);
}

echo $result->data;
