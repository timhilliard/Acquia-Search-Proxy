Search proxy
======

Allows search proxying against Acquia Search. Also provides method for
testing search queries.


Configuration
-------------

    
    $settings = array(
      'node_access' => TRUE, // This is a security setting. Whether or not the user has node access permissions.
      'allowed_ip' => array( // What IPs are allowed to call this proxy script.
        '127.0.0.1',
      ),
      'acquia_identifier' => 'GTWX-10000', // The Acquia account identifier. e.g. GTWX-10000
      'derived_key' => 'some_hash_generated', // Run drush php-eval 'echo _acquia_search_derived_key();'
      // Note: The derived_key is NOT your acquia key and needs to be generated using the drush line above.
    );
    

Fill in the acquia_identifier and derived_key to allow searching. If these settings are omitted or incorrect
you will get Access Denied 403 errors.

Usage
-----

http://localhost/search-proxy.php/select?q=test

* select - the operation to perform against Acquia Search.
* q - the query to run against Acquia Search.


Example
-------

http://localhost/search-proxy.php/select?q=test
    
    <response>
      <lst name="responseHeader">
        <int name="status">0</int>
        <int name="QTime">2</int>
        <lst name="params">
          <str name="request_id">4f2c136fe61a0</str>
          <str name="q">test</str>
        </lst>
      </lst>
      <result name="response" numFound="0" start="0"/>
      <lst name="highlighting"/>
    </response>
    
