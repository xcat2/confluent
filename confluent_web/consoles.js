$(document).ready(function() {

  $.getJSON("/confluent-api/nodes/", function( data) {
	var items = [];
	var options = [];
	var nodename = "";
	$.each( data["_links"]["item"], function( key, val ) {
        if (typeof(val) == "object") {
		    nodename = val.href;
        } else {
            nodename = val;
        }
		nodename = nodename.replace('/', '');
        $("#nodes").append("<button id="+nodename+">"+nodename+"</button><br>");
        $("#"+nodename).button().click(function( event ) {
            var tname = this.id;
            var url  = "/confluent-api/nodes/" + tname + "/console/session";
            new ConsoleWindow(url, tname);
        });
	});
  });
}); // end document
