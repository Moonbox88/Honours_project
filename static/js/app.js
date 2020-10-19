$(function() {
	$('a#device-submit').bind('click', function() {
		$.getJSON('/device_scan', {
			gateway_ip: $('input[name="default-gateway"]').val(),
			public_ip: $('input[name="public-ip"]').val(),
		}, function(data) {
			$.each(data, function(index, value) {
				for(i = 0; i < value.length; i++) {
					var $device_elem = $('tbody.device-section');
					$device_elem.append(
						$('<tr/>').append(
							$('<td/>', {text: value[i].IP_address})
						).append(
							$('<td/>', {text: value[i].Manufacturer})
						).append(
							$('<td/>', {text: value[i].MAC_address})
						).append(
							$('<td/>', {text: value[i].OS_details})
						)
					)
					var $ipsniff_elem = $('div#sniff-ip-list');
					//var func = 'fillSniffIP(' + value[i].IP_address + ')'
					$ipsniff_elem.append(
						$('<a/>', {'class': 'dropdown-item', 'href': '#', 'name': 'sniff-ip', 'onClick': 'selectSniffIP(\'' + value[i].IP_address + '\')', text: value[i].IP_address})
							//$('<input/>', {'type': 'hidden', 'name': 'sniff-ip', 'value': value[i].IP_address})
						
					)
				};
			});
		});
		return false;
	});
});


$(function() {
	$('a#run-packet-sniff').click(function() {
		$.ajax({
			url: '/packet_sniff',
			success: function(data) {
				alert(data.die);
			},
			dataType: 'JSON',
			type: 'GET',
			error: function() {
				alert("nein");
			}
		});
	});
});
				

