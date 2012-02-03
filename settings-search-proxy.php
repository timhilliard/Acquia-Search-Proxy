<?php

$settings = array(
  'node_access' => FALSE, // This is a security setting. Whether or not the user has node access permissions.
  'allowed_ip' => array( // What IPs are allowed to call this proxy script.
    '127.0.0.1',
  ),
  'acquia_identifier' => '', // The Acquia account identifier. e.g. GTWX-10000
  'derived_key' => '', // Run drush php-eval 'echo _acquia_search_derived_key();'
  // Note: The derived_key is NOT your acquia key and needs to be generated using the drush line above.
);
