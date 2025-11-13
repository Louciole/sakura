import global from "/static/framework/global.mjs"
// import {initWebSockets} from "./framework/websockets.mjs";
import {initNavigation, printWatermark} from "./framework/navigation.mjs";
import {initTranslations} from "./translations/translation.mjs";

// initWebSockets()
initNavigation()
await initTranslations()
printWatermark("emptyProject@carbonlab.dev", "gitlab.com/louciole/emptyProject")
