use strict;
use warnings;

use Confluent::Client;

my $client = Confluent::Client->new();
$client->read('/nodes/n1/power/state');
my $data = $client->next_result();
while ($data) {
    if (exists $data->{state}) {
        print $data->{state}->{value} . "\n";
    }
    $data = $client->next_result();
}
