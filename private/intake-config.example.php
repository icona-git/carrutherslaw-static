<?php
declare(strict_types=1);
// Shape of <vhost-root>/private/intake-config.php on Betty. The real file is
// created on the server (mode 600, owner = vhost sysuser) and never committed.
return [
    'MAILGUN_API_BASE'     => 'https://api.mailgun.net/v3',
    'MAILGUN_DOMAIN'       => 'mg.carrutherslaw.ca',
    'MAILGUN_SENDING_KEY'  => 'key-REPLACE-WITH-REAL-MAILGUN-SENDING-KEY',
    'MAIL_TO'              => ['ian@carrutherslaw.ca'],
    'MAIL_BCC'             => [],
    'MAIL_FROM'            => 'Carruthers Law Website <website@carrutherslaw.ca>',
    'MAIL_SUBJECT'         => 'Website inquiry',
    'RECAPTCHA_SECRET'     => 'REPLACE-WITH-REAL-RECAPTCHA-SECRET',
    'LEADS_DIR'            => null,
    'RATE_DIR'             => null,
    'RATE_LIMIT'           => 5,
    'RATE_WINDOW'          => 600,
    'DRY_RUN'              => false,
    'TRUSTED_PROXY_HEADER' => null,
];
