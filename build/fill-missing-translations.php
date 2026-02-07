<?php
/**
 * Fill missing PO translations with source strings.
 *
 * This is a pragmatic fallback pass so every locale has complete catalogs.
 * It keeps existing translations and only fills empty msgstr values.
 *
 * Usage:
 *   php build/fill-missing-translations.php
 */

if ( php_sapi_name() !== 'cli' ) {
	die( "CLI only.\n" );
}

$lang_dir = dirname( __DIR__ ) . '/languages';
$po_files = glob( $lang_dir . '/nexifymy-security-*.po' );

if ( empty( $po_files ) ) {
	die( "No PO files found in {$lang_dir}\n" );
}

$total_updated = 0;

foreach ( $po_files as $po_file ) {
	$lines = file( $po_file, FILE_IGNORE_NEW_LINES );
	if ( false === $lines ) {
		echo "Skipping unreadable file: {$po_file}\n";
		continue;
	}

	$current_msgid = null;
	$updated = 0;
	$line_count = count( $lines );

	for ( $i = 0; $i < $line_count; $i++ ) {
		$line = $lines[ $i ];

		if ( preg_match( '/^msgid\s+"(.*)"$/', $line, $matches ) ) {
			$current_msgid = stripcslashes( $matches[1] );
			continue;
		}

		if ( preg_match( '/^msgstr\s+""$/', $line ) ) {
			// Skip header entry.
			if ( null === $current_msgid || '' === $current_msgid ) {
				continue;
			}

			// Fill missing translation with source string.
			$lines[ $i ] = 'msgstr "' . addcslashes( $current_msgid, "\\\"\n\r\t" ) . '"';
			$updated++;
		}
	}

	file_put_contents( $po_file, implode( "\n", $lines ) . "\n" );
	$total_updated += $updated;

	echo basename( $po_file ) . ": filled {$updated} entries\n";
}

echo "Done. Total filled entries: {$total_updated}\n";

