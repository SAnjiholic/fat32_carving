#!/usr/bin/env perl
use strict;

my $filename = $ARGV[0];

open(F,"<$filename") or die("Unable to open file $filename, $!");
read(F, my $buf, 0x200);

my ($dummy1, $byte_sec, $sec_clust, $reserved, $fat_count, $dummy2,$hidden_sec, $total_sec, $fat_size, $dummy3, $root_dir) = unpack("A11 v C1 v C1 A11 V  V V A4 V",$buf); 

printf ("byte : 0x%04x\n",$byte_sec);
printf ("sec_clust : 0x%04x\n", $sec_clust);
printf ("reserved : 0x%04x\n", $reserved);
printf ("fat count : 0x%02x\n", $fat_count);
printf ("hidden : 0x%08x\n", $hidden_sec);
printf ("total_sec : 0x%08x\n", $total_sec);
printf ("fat_size : 0x%08x\n", $fat_size);
printf ("root_dir : 0x%08x\n", $root_dir); 

seek(F,($reserved * $byte_sec),0);
read(F, $buf, ($fat_size * $byte_sec));

my @clust = unpack("V*",$buf);
my $index = 0;
my @empty;

foreach(@clust){
	push(@empty,$index) unless ($_);
	$index++;
}

#foreach my $number (@empty){
foreach (0 .. $#empty){
	my $number = $empty[$_];
	my $offset = $number * 0x200;
	seek(F, $offset,0);
	read(F, $buf, ($byte_sec * $sec_clust ));
	&find($number,$buf);
}

sub find()
{
	my ($number,$buf) = @_;
	my $signature_l = unpack("V",$buf);
	my $signature_b = unpack("N",$buf);
	my $ret = &format($signature_b,$signature_l);
	print "$number => $ret \n" if ($ret);
	&zip($buf) if($signature_b == 0x504B0304);
	
}

sub zip()
{
	my $buf = shift;
	my $count = length($buf);
	my $index = 0;
	while ($count > $index){
		my $tt = $index +26;
		my ($dummy1,$tmp) = unpack ("A$tt v",$buf);
		my($sig, $dummy,$data, $len1, $len2, $name) = unpack("N A18 V v v A$tmp",$buf);
		print "\t Zip >>  $name\n";
		$index += $len1+$len2+$data+22;
	}
}
sub format()
{
	my %hash;
	$hash{0xf5} =  'DBF';
	$hash{0xfF} =  'SYS';
	$hash{0x08} =  'DB';
	$hash{0x80} =  'OBJ';
	$hash{0x7B} =  'DBF';
	$hash{0x83} =  'DBF';
	$hash{0xe8} =  'COM,SYS';
	$hash{0x8B} =  'DBF';
	$hash{0x78} =  'DMG';
	$hash{0x5854} =  'BDR';
	$hash{0x60EA} =  'ARJ';
	$hash{0x0CED} =  'MP';
	$hash{0x2320} =  'MSI';
	$hash{0x424D} =  'BMP,DIB';
	$hash{0x4C01} =  'OBJ';
	$hash{0x4D5A} = 'PE';
	$hash{0x4D56} =  'DSN';
	$hash{0x4F7B} =  'DW4';
	$hash{0x9501} =  'SKR';
	$hash{0x9900} =  'PKR';
	$hash{0x9901} =  'PKR';
	$hash{0x9BA5} =  'DOC';
	$hash{0xd42A} =  'ARL,AUT';
	$hash{0xdBA5} =  'DOC';
	$hash{0xdCDC} =  'CPL';
	$hash{0xdCFE} =  'EFX';
	$hash{0xfEDB} =  'SEQ';
	$hash{0x50C3} =  'CLP';
	$hash{0xfFFF} =  'GEM';
	$hash{0x81CDAB} =  'WPF';
	$hash{0x50350A} =  'PGM';
	$hash{0x1F8B08} =  'GZ';
	$hash{0x1F9D90} =  'TAR.Z';
	$hash{0x425A68} =  'BZ2,TAR,||TBZ2,TB2';
	$hash{0x000101} =  'FLT';
	$hash{0x435753} =  'SWF';
	$hash{0x444F53} =  'ADF';
	$hash{0x464C56} =  'SWF';
	$hash{0x465753} =  'SWF';
	$hash{0x475832} =  'GX2';
	$hash{0x4D4D2A} =  'TIF,TIFF';
	$hash{0x4D4743} =  'CRD';
	$hash{0x494433} =  'MP3';
	$hash{0x4D534346} =  'CAB||PPZ||SNP';
	$hash{0x4D4C5357} =  'MLS';
	$hash{0x4D4D002A} =  'TIF,TIFF';
	$hash{0x4D4D002B} =  'TIF,TIFF';
	$hash{0x4C4E0200} =  'HLP';
	$hash{0x4C696E53} =  'MSP';
	$hash{0x49424B1A} =  'IBK';
	$hash{0x494D4443} =  'IC1,IC2,IC3';
	$hash{0x49536328} =  'CAB';
	$hash{0x49545346} =  'CHM';
	$hash{0xFFD8FFE0} = 'JPEG';
	$hash{0xFFD8FFE8} = 'JPEG'; 
	$hash{0x00010008} =  'IMG';
	$hash{0x00014241} =  'ABA';
	$hash{0x00014244} =  'DBA';
	$hash{0x0D444F43} =  'DOC';
	$hash{0x0F00E803} =  'PPT';
	$hash{0x25504446} =  'PDF||FDF';
	$hash{0x414C5A01} =  'ALZ';
	$hash{0x434F4D2B} =  'CLB';
	$hash{0x43524547} =  'DAT';
	$hash{0x414D594F} =  'SYW';
	$hash{0x43544D46} =  'CMF';
	$hash{0x44424648} =  'DB';
	$hash{0x444D5321} =  'DMS';
	$hash{0x44616E4D} =  'MSP';
	$hash{0x47504154} =  'PAT';
	$hash{0x4C000000} =  'LNK';
	$hash{0x4D563243} =  'MLS';
	$hash{0x5041434B} =  'PAK';
	$hash{0x50455354} =  'DAT';
	$hash{0x504B0304} =  'ZIP';
	$hash{0x504D4343} =  'GRP';
	$hash{0x51454C20} =  'QEL';
	$hash{0x514649FB} =  'IMG';
	$hash{0x52545353} =  'CAP';
	$hash{0x5342491A} =  'SBI';
	$hash{0x5343486C} =  'AST';
	$hash{0x53434D49} =  'IMG';
	$hash{0x53484F57} =  'SHW';
	$hash{0x536D626C} =  'SYM';
	$hash{0x55434558} =  'UCE';
	$hash{0x56445649} =  'AVS';
	$hash{0x7A626578} =  'INFO';
	$hash{0x574D4D50} =  'DAT';
	$hash{0x58435000} =  'CAP';
	$hash{0x59A66A95} =  'RAS';
	$hash{0x736C6821} =  'DATgg';
	$hash{0x5A4F4F20} =  'ZOO';
	$hash{0x64000000} =  'P10';
	$hash{0x6D6F6F76} =  'MOVgg';
	$hash{0x72656766} =  'DAT';
	$hash{0x737A657A} =  'PDB';
	$hash{0xeCA5C100} =  'DOC';
	$hash{0xe3828596} =  'PWL';
	$hash{0xc3ABCDAB} =  'ACS';
	$hash{0xc5D0D3C6} =  'EPS';
	$hash{0xc8007900} =  'LBK';
	$hash{0xcAFEBABE} =  'CLASS';
	$hash{0x91334846} =  'HAP';
	$hash{0x7E424B00} =  'PSP';
	$hash{0xa0461DF0} =  'PPT';
	$hash{0xb168DE3A} =  'DCX';
	$hash{0xbABEEBEA} =  'ANI';
	$hash{0xcFAD12FE} =  'DBX';
	$hash{0xd20A0000} =  'FTR';
	$hash{0xeB3C902A} =  'IMG';
	$hash{0xd7CDC69A} =  'WMF';
	$hash{0x4D546864} =  'MID,MIDI';
	$hash{0xeDABEEDB} =  'RPM';
	$hash{0x5B4D535643} =  'VCW';
	$hash{0xfDFFFFFF04} =  'SUO';
	$hash{0xeF464F4E54} =  'CPI';
	$hash{0x7B0D0A6F20} =  'LGC,LGD';
	$hash{0x7573746172} =  'TAR';
	$hash{0x4D494C4553} =  'MLS';
	$hash{0x4344303031} =  'ISO';
	$hash{0x4D56323134} =  'MLS';
	$hash{0x4E49544630} =  'NTF';
	$hash{0x504B537058} =  'ZIP';
	$hash{0x5349542100} =  'SIT';
	$hash{0x4848474231} =  'SH3';
	$hash{0x575332303030} =  'WS2';
	$hash{0x57696E5A6970} =  'ZIP';
	$hash{0x5F434153455F} =  'CAS,CBK';
	$hash{0x4E45534D1A01} =  'NFS';
	$hash{0x4E616D653A20} =  'COD';
	$hash{0x504943540008} =  'IMG';
	$hash{0x504B4C495445} =  'ZIP';
	$hash{0x564350434830} =  'PCH';
	$hash{0x31BE000000AB} =  'DOC';
	$hash{0x377ABCAF271C} =  '7Z';
	$hash{0x474946383761} =  'GIF';
	$hash{0x474946383961} =  'GIF';
	$hash{0x4A4152435300} =  'JAR';
	$hash{0x4D4D4D440000} =  'MMF';
	$hash{0xaC9EBD8F0000} =  'QDF';
	$hash{0x7B5C72746631} =  'RTF';
	$hash{0x80000020031204} =  'ADX';
	$hash{0x424C4932323351} =  'BIN';
	$hash{0x43525553482076} =  'CRU';
	$hash{0x4B030414000800} =  'JAR';
	$hash{0x52454745444954} =  'REG,SUD';
	$hash{0x526172211A0700} =  'RAR';
	$hash{0x5B50686F6E655D} =  'DUN';
	$hash{0x64737766696C65} =  'DSW';
	$hash{0xfF4B455942202020} =  'SYS';
	$hash{0x0006156100000002} =  'DB';
	$hash{0x0000001866747970} =  'MP4gg';
	$hash{0x3026B2758E66CF11} =  'ASF,WMA,||WMV';
	$hash{0x4554465353415645} =  'DAT';
	$hash{0x4746315041544348} =  'PAT';
	$hash{0x496E6E6F20536574} =  'DATgg';
	$hash{0x4D53465402000100} =  'TLB';
	$hash{0x4D535F564F494345} =  'CDR,DVF,||MSV';
	$hash{0x4D5A900003000000} =  'API,||AX,||FLT';
	$hash{0x4D5A900003000000} =  'ZAP';
	$hash{0x4D6963726F736F66} =  'SLNgg';
	$hash{0x4D6963726F736F66} =  'WPLgg';
	$hash{0x4E41565452414646} =  'DATgg';
	$hash{0x4F504C4461746162} =  'DBFgg';
	$hash{0x4F67675300020000} =  'OGA,OGG,||OGV,OGX';
	$hash{0x5000000020000000} =  'IDX';
	$hash{0x504B030414000600} =  'DOCX,PPTX,||XLSX';
	$hash{0x5157205665722E20} =  'ABD,QSD';
	$hash{0x52415A4154444231} =  'DAT';
	$hash{0x5245564E554D3A2C} =  'ADF';
	$hash{0x53494554524F4F49} =  'CPIgg';
	$hash{0x534D415254445257} =  'SDR';
	$hash{0x53514C4F434F4E56} =  'CNVgg';
	$hash{0x5468697320697320} =  'INFO';
	$hash{0x55464F4F72626974} =  'DAT';
	$hash{0x56455253494F4E20} =  'CTL';
	$hash{0x5850434F4D0A5479} =  'XPTgg';
	$hash{0x5B47656E6572616C} =  'ECFgg';
	$hash{0x5B5645525D0D0A09} =  'SAM';
	$hash{0x5B56657273696F6E} =  'CIF';
	$hash{0x5B57696E646F7773} =  'CPXgg';
	$hash{0x5B666C7473696D2E} =  'CFGgg';
	$hash{0x6375736800000002} =  'CSH';
	$hash{0x664C614300000022} =  'FLAC';
	$hash{0x737263646F636964} =  'CALgg';
	$hash{0x74424D504B6E5772} =  'PRC';
	$hash{0x89504E470D0A1A0A} =  'PNG';
	$hash{0x8A0109000000E108} =  'AW';
	$hash{0x9CCBCB8D1375D211} =  'WAB';
	$hash{0xa90D000000000000} =  'DAT';
	$hash{0xbE000000AB000000} =  'WRI';
	$hash{0xcF11E0A1B11AE100} =  'DOC';
	$hash{0xe310000100000000} =  'INFO';
	$hash{0x76323030332E3130} =  'FLTgg';
	$hash{0xfDFFFFFF20000000} =  'OPT||XLS';
	$hash{0xfF00020004040554} =  'WKS';
	
	my ($li,$bi) = @_;
	if ($hash{$bi}){return $hash{$bi}}
	if ($hash{$li}){return $hash{$li}} 
	return undef;


}

