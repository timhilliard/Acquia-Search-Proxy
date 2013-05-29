<?php

$settings = array(
  'node_access' => TRUE, // This is a security setting. Whether or not the user has node access permissions.
  'allowed_ip' => array( // What IPs are allowed to call this proxy script.
    '127.0.0.1',
  ),
  'host' => 'search.acquia.com', // By default use search.acquia.com
  'acquia_identifier' => '', // The Acquia account identifier. e.g. GTWX-10000
  /*
   * Note: The derived_key is NOT your acquia key and needs to be generated using the drush line above.
   * Please execute the following command:
   *   drush php-eval 'echo _acquia_search_derived_key();' (for Apachesolr)
   * or:
   *   drush php-eval 'echo SearchApiAcquiaSearchHttpTransport::getDerivedKey();' (for Search API)
   */
  'derived_key' => '',
);

