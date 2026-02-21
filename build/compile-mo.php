<?php
/**
 * Compile a PO file into an MO file.
 *
 * Usage:
 *   php build/compile-mo.php <input.po> <output.mo>
 */

if ( php_sapi_name() !== 'cli' ) {
	die( "CLI only.\n" );
}

if ( $argc < 3 ) {
	die( "Usage: php build/compile-mo.php <input.po> <output.mo>\n" );
}

$input  = $argv[1];
$output = $argv[2];

if ( ! file_exists( $input ) ) {
	die( "Input file not found: {$input}\n" );
}

$po_content = file_get_contents( $input );
if ( false === $po_content ) {
	die( "Unable to read input file: {$input}\n" );
}

$entries = parse_po_entries( $po_content );
$mo_data = generate_mo_binary( $entries );

if ( false === file_put_contents( $output, $mo_data ) ) {
	die( "Failed to write output file: {$output}\n" );
}

echo 'Compiled ' . basename( $input ) . ' -> ' . basename( $output ) . ' (' . count( $entries ) . " entries)\n";

/**
 * Parse PO content into MO key/value pairs.
 *
 * @param string $content PO file content.
 * @return array<string, string>
 */
function parse_po_entries( $content ) {
	$lines = preg_split( "/\r\n|\n|\r/", $content );
	if ( ! is_array( $lines ) ) {
		return array();
	}

	$entries     = array();
	$current     = init_po_entry();
	$current_key = null;
	$current_idx = null;

	foreach ( $lines as $line ) {
		$trim = trim( $line );

		if ( '' === $trim ) {
			finalize_po_entry( $entries, $current );
			$current     = init_po_entry();
			$current_key = null;
			$current_idx = null;
			continue;
		}

		if ( '#' === substr( $trim, 0, 1 ) ) {
			continue;
		}

		if ( preg_match( '/^msgctxt\s+(".*")$/', $trim, $m ) ) {
			$current_key          = 'msgctxt';
			$current_idx          = null;
			$current['msgctxt']   = decode_po_quoted( $m[1] );
			$current['has_entry'] = true;
			continue;
		}

		if ( preg_match( '/^msgid_plural\s+(".*")$/', $trim, $m ) ) {
			$current_key             = 'msgid_plural';
			$current_idx             = null;
			$current['msgid_plural'] = decode_po_quoted( $m[1] );
			$current['has_entry']    = true;
			continue;
		}

		if ( preg_match( '/^msgid\s+(".*")$/', $trim, $m ) ) {
			$current_key          = 'msgid';
			$current_idx          = null;
			$current['msgid']     = decode_po_quoted( $m[1] );
			$current['has_entry'] = true;
			continue;
		}

		if ( preg_match( '/^msgstr\[(\d+)\]\s+(".*")$/', $trim, $m ) ) {
			$current_key = 'msgstr_plural';
			$current_idx = (int) $m[1];
			if ( ! isset( $current['msgstr_plural'][ $current_idx ] ) ) {
				$current['msgstr_plural'][ $current_idx ] = '';
			}
			$current['msgstr_plural'][ $current_idx ] .= decode_po_quoted( $m[2] );
			$current['has_entry']                      = true;
			continue;
		}

		if ( preg_match( '/^msgstr\s+(".*")$/', $trim, $m ) ) {
			$current_key          = 'msgstr';
			$current_idx          = null;
			$current['msgstr']    = decode_po_quoted( $m[1] );
			$current['has_entry'] = true;
			continue;
		}

		if ( preg_match( '/^(".*")$/', $trim, $m ) ) {
			$part = decode_po_quoted( $m[1] );
			if ( 'msgctxt' === $current_key ) {
				$current['msgctxt'] .= $part;
			} elseif ( 'msgid' === $current_key ) {
				$current['msgid'] .= $part;
			} elseif ( 'msgid_plural' === $current_key ) {
				$current['msgid_plural'] .= $part;
			} elseif ( 'msgstr' === $current_key ) {
				$current['msgstr'] .= $part;
			} elseif ( 'msgstr_plural' === $current_key && null !== $current_idx ) {
				$current['msgstr_plural'][ $current_idx ] .= $part;
			}
		}
	}

	finalize_po_entry( $entries, $current );
	return $entries;
}

/**
 * Initialize a PO entry container.
 *
 * @return array<string, mixed>
 */
function init_po_entry() {
	return array(
		'has_entry'     => false,
		'msgctxt'       => '',
		'msgid'         => null,
		'msgid_plural'  => null,
		'msgstr'        => '',
		'msgstr_plural' => array(),
	);
}

/**
 * Finalize parsed PO entry into MO dictionary.
 *
 * @param array<string, string> $entries  MO entries dictionary.
 * @param array<string, mixed>  $current  Current parsed PO entry.
 * @return void
 */
function finalize_po_entry( &$entries, $current ) {
	if ( empty( $current['has_entry'] ) || null === $current['msgid'] ) {
		return;
	}

	$msgctxt      = (string) $current['msgctxt'];
	$msgid        = (string) $current['msgid'];
	$msgid_plural = $current['msgid_plural'];

	if ( null !== $msgid_plural ) {
		$plural_forms = $current['msgstr_plural'];
		if ( ! is_array( $plural_forms ) ) {
			$plural_forms = array();
		}
		ksort( $plural_forms );
		$max_index      = empty( $plural_forms ) ? -1 : (int) max( array_keys( $plural_forms ) );
		$compiled_forms = array();
		for ( $i = 0; $i <= $max_index; $i++ ) {
			$compiled_forms[] = isset( $plural_forms[ $i ] ) ? (string) $plural_forms[ $i ] : '';
		}
		$translation = implode( "\0", $compiled_forms );
		$is_header   = ( '' === $msgid );
		if ( '' === str_replace( "\0", '', $translation ) && ! $is_header ) {
			return;
		}

		$original = $msgid . "\0" . (string) $msgid_plural;
		if ( '' !== $msgctxt ) {
			$original = $msgctxt . "\004" . $original;
		}
		$entries[ $original ] = $translation;
		return;
	}

	$translation = (string) $current['msgstr'];
	$is_header   = ( '' === $msgid );
	if ( '' === $translation && ! $is_header ) {
		return;
	}

	$original = $msgid;
	if ( '' !== $msgctxt ) {
		$original = $msgctxt . "\004" . $original;
	}

	$entries[ $original ] = $translation;
}

/**
 * Decode a quoted PO string.
 *
 * @param string $quoted Quoted PO fragment (for example: "\"Hello\"").
 * @return string
 */
function decode_po_quoted( $quoted ) {
	$quoted = trim( (string) $quoted );
	if ( strlen( $quoted ) >= 2 && '"' === $quoted[0] && '"' === substr( $quoted, -1 ) ) {
		$quoted = substr( $quoted, 1, -1 );
	}
	return stripcslashes( $quoted );
}

/**
 * Build MO binary content from entries.
 *
 * @param array<string, string> $entries MO entries.
 * @return string
 */
function generate_mo_binary( $entries ) {
	if ( ! isset( $entries[''] ) ) {
		$entries[''] = '';
	}

	ksort( $entries, SORT_STRING );

	$count              = count( $entries );
	$originals          = array_keys( $entries );
	$translations       = array_values( $entries );
	$header_size        = 28;
	$original_table_off = $header_size;
	$translation_off    = $original_table_off + ( $count * 8 );
	$string_off         = $translation_off + ( $count * 8 );

	$original_table    = '';
	$translation_table = '';
	$strings           = '';

	foreach ( $originals as $original ) {
		$len             = strlen( $original );
		$original_table .= pack( 'V2', $len, $string_off + strlen( $strings ) );
		$strings        .= $original . "\0";
	}

	foreach ( $translations as $translation ) {
		$len                = strlen( $translation );
		$translation_table .= pack( 'V2', $len, $string_off + strlen( $strings ) );
		$strings           .= $translation . "\0";
	}

	$header = pack(
		'V7',
		0x950412de,
		0,
		$count,
		$original_table_off,
		$translation_off,
		0,
		$translation_off + ( $count * 8 )
	);

	return $header . $original_table . $translation_table . $strings;
}
