<?php

$settings = array(
  'node_access' => FALSE, // This is a security setting. Whether or not the user has node access permissions.
  'allowed_ip' => array( // What IPs are allowed to call this proxy script.
    '127.0.0.1',
  ),
  'acquia_identifier' => '', // The Acquia account identifier. e.g. GTWX-10000
    
  // You need to set either the acquia_key and derived_key_salt or just the derived key.
  // NOTE: Currently only the derived_key method works.
  'acquia_key' => '', // The Acquia key.
  'derived_key_salt' => '', // ToDo: pull this value directly from the Acquia network.
    
  'derived_key' => '', // Run drush php-eval 'echo _acquia_search_derived_key();'
);
