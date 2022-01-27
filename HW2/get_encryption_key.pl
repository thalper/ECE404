#!/usr/bin/perl -w

##  get_encryption_key.pl

##  Avi Kak
##  January 14, 2018

##  This scripts asks the user to supply eight characters (exactly) for
##  the encryption key needed for DES based encryption/decryption.

use strict;
use Algorithm::BitVector;

my $key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                          9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                         62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                         13,5,60,52,44,36,28,20,12,4,27,19,11,3];

my $key = get_encryption_key();
print "Here is the 56-bit encryption key generated from your input:\n";
print "$key\n";

sub get_encryption_key {
    my $key = "";
    print "\nEnter a string of 8 characters for the key: ";
    while ( $key = <STDIN> ) {
        chomp $key;
        if (length $key != 8) {
            print "\nKey generation needs 8 characters exactly.  Try again: ";
            next;
        } else {
            last;
        }
    }
    $key = Algorithm::BitVector->new( textstring => $key );
    $key = $key->permute($key_permutation_1);
    return $key
}
