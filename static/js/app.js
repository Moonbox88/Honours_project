$(function() {
	$('a#device-submit').bind('click', function() {
		$.getJSON('/device_scan', {
			gateway_ip: $('input[name="default-gateway"]').val(),
			public_ip: $('input[name="public-ip"]').val(),
		}, function(data) {
			$.each(data, function(index, value) {
				$("tr").remove(".device-info");
				$('a#sniff-ip').remove();
				for(i = 0; i < value.length; i++) {
					var $device_elem = $('tbody.device-section');
					$device_elem.append(
						$('<tr/>', {'class': 'device-info'}).append(
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
					var func = "passSniff.call('" + value[i].IP_address + "')";
					$ipsniff_elem.append(
						$('<a/>', {'class': 'dropdown-item', 'href': '#', 'id': 'sniff-ip', 'onclick': func, text: value[i].IP_address})

					)
				};
			});
		});
		return false;
	});
});


$(function() {
	$('a#run-packet-sniff').bind('click', function() {
		$.getJSON('/packet_sniff', {
			// GET IP PLACEHOLDER FOR ARPSPOOF
		}, function(data) {
			$.each(data, function(index, value) {
				if (index == 1) {
					var packet_file = value;
					var canvas = document.getElementById("bigDashboardChart");
					var ctx = canvas.getContext("2d");
					ctx.font = "10px Arial";
					$.get(packet_file,function(txt) {
						var lines = txt.responseText.split("\n");
						for (var i = 0, len = lines.length; i < len; i++) {
							c
						}
					});
				}
			});
		});
		return false;
	});
});
				

