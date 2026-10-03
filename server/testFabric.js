const {
  connectToFabric,
  getDefense,
  getAllDefenses,
} = require("./fabricClient");

async function main() {
  try {
    console.log("Connecting to Fabric...");

    connectToFabric();

    console.log("Fabric connection successful.");

    console.log("\nReading INC-TEST-001...");

    const defense =
      await getDefense("INC-TEST-001");

    console.log(
      JSON.stringify(defense, null, 2)
    );

    console.log("\nReading all defenses...");

    const defenses =
      await getAllDefenses();

    console.log(
      JSON.stringify(defenses, null, 2)
    );

    process.exit(0);
  } catch (error) {
    console.error("\nFabric connection failed:");
    console.error(error);

    process.exit(1);
  }
}

main();