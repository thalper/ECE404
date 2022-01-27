#!/usr/bin/perl -w

##  get_encryption_key.pl

##  Avi Kak
##  January 14, 2018

##  This scripts asks the user to supply eight characters (exactly) for
##  the encryption key needed for DES based encryption/decryption.
##  It subsequently generates the round keys for each of the 16 rounds
##  of DES.

use strict;
use Algorithm::BitVector;

my $key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                          9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                         62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                         13,5,60,52,44,36,28,20,12,4,27,19,11,3];

my $key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
                          3,25,7,15,6,26,19,12,1,40,51,30,36,46,
                         54,29,39,50,44,32,47,43,48,38,55,33,52,
                         45,41,49,35,28,31];

my $shifts_for_round_key_gen = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

my $encryption_key = get_encryption_key();
my @round_keys = generate_round_keys($encryption_key);
print "\nHere are the 16 round keys:\n";
foreach my $round_key (@round_keys) {
    print "$round_key\n";
}

sub generate_round_keys {
    my $encryption_key = shift;
    my @round_keys = ();
    my $key = $encryption_key->deep_copy();
    foreach my $round_count (0..15) {
        my ($LKey, $RKey) = $key->divide_into_two();
        my $shift = $shifts_for_round_key_gen->[$round_count];
        $LKey = $LKey << $shift;
        $RKey = $RKey << $shift;
        $key = $LKey + $RKey;
        my $round_key = $key->permute($key_permutation_2);
        push @round_keys, $round_key;
    }
    return @round_keys;
}

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
