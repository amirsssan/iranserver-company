#!/bin/bash

BASE="/home"
DOMAIN="irandns.com"

# ==============================================================
# TEMP FILES
# ==============================================================

TMP_IRAN=$(mktemp)
TMP_FOREIGN=$(mktemp)
TMP_UNKNOWN=$(mktemp)

trap 'rm -f "$TMP_IRAN" "$TMP_FOREIGN" "$TMP_UNKNOWN"' EXIT


# ==============================================================
# GEOIP
# ==============================================================

get_country() {

    local IP="$1"
    local DB=""
    local RESULT=""

    # ----------------------------------------------------------
    # Find MaxMind database
    # ----------------------------------------------------------

    for FILE in \
        /usr/share/GeoIP/GeoLite2-Country.mmdb \
        /usr/share/GeoIP/GeoIP2-Country.mmdb \
        /usr/local/share/GeoIP/GeoLite2-Country.mmdb \
        /usr/local/share/GeoIP/GeoIP2-Country.mmdb
    do
        if [ -f "$FILE" ]; then
            DB="$FILE"
            break
        fi
    done


    # ----------------------------------------------------------
    # mmdblookup
    # ----------------------------------------------------------

    if [ -n "$DB" ] && command -v mmdblookup >/dev/null 2>&1; then

        RESULT=$(
            mmdblookup \
                --file "$DB" \
                --ip "$IP" \
                country iso_code 2>/dev/null |
            grep -oE '"[A-Z]{2}"' |
            tr -d '"' |
            head -1
        )

        if [ -n "$RESULT" ]; then
            echo "$RESULT"
            return
        fi
    fi


    # ----------------------------------------------------------
    # geoiplookup
    # ----------------------------------------------------------

    if command -v geoiplookup >/dev/null 2>&1; then

        RESULT=$(
            geoiplookup "$IP" 2>/dev/null |
            head -1 |
            sed -n 's/.*: \([A-Z][A-Z]\),.*/\1/p'
        )

        if [ -n "$RESULT" ]; then
            echo "$RESULT"
            return
        fi
    fi


    echo "UNKNOWN"
}


# ==============================================================
# SIZE FUNCTION
# ==============================================================

human_size() {

    local BYTES="$1"

    if [ "$BYTES" -eq 0 ]; then
        echo "0B"
    else
        numfmt --to=iec --suffix=B "$BYTES" 2>/dev/null || echo "0B"
    fi
}


# ==============================================================
# BACKUP SCANNER
#
# Recursive on purpose:
#   LH   -> direct files
#   WH   -> direct files
#   SONIC -> date directories
# ==============================================================

scan_backup_dir() {

    local DIR="$1"
    local COUNT=0
    local BYTES=0

    if [ ! -d "$DIR" ]; then
        echo "0 0"
        return
    fi

    while IFS=$'\t' read -r SIZE FILE; do

        [ -z "$SIZE" ] && continue

        COUNT=$((COUNT + 1))
        BYTES=$((BYTES + SIZE))

    done < <(
        find "$DIR" \
            -type f \
            -printf '%s\t%p\n'
    )

    echo "$COUNT $BYTES"
}


# ==============================================================
# HEADER
# ==============================================================

echo
echo "=============================================================="
echo "              BACKUP INVENTORY REPORT"
echo "=============================================================="
echo "Base Path : $BASE"
echo "Domain    : $DOMAIN"
echo "Started   : $(date)"
echo "=============================================================="


# ==============================================================
# FIND ALL LH / WH / SONIC
# ==============================================================

for SERVER_DIR in \
    "$BASE"/lh* \
    "$BASE"/wh* \
    "$BASE"/sonic*
do

    [ -d "$SERVER_DIR" ] || continue

    SERVER=$(basename "$SERVER_DIR")

    # ----------------------------------------------------------
    # Only:
    # lh123
    # wh123
    # sonic1234
    # ----------------------------------------------------------

    if [[ ! "$SERVER" =~ ^(lh|wh|sonic)[0-9]+$ ]]; then
        continue
    fi


    HOST="${SERVER}.${DOMAIN}"


    # ==========================================================
    # DNS
    # ==========================================================

    IP=$(
        getent ahostsv4 "$HOST" 2>/dev/null |
        awk 'NR==1 {print $1}'
    )


    # ==========================================================
    # NO IP
    # ==========================================================

    if [ -z "$IP" ]; then

        LINE=$(printf "%-10s %-16s %-12s %8s / %-9s %8s / %-9s %-16s" \
            "$SERVER" \
            "-" \
            "NO-IP" \
            "-" \
            "-" \
            "-" \
            "-" \
            "NO-BACKUP"
        )

        echo "$LINE" >> "$TMP_UNKNOWN"

        continue
    fi


    # ==========================================================
    # GEOIP
    # ==========================================================

    COUNTRY=$(get_country "$IP")

    case "$COUNTRY" in

        IR)
            LOCATION="IRAN"
            ;;

        UNKNOWN|"")
            LOCATION="UNKNOWN"
            ;;

        *)
            LOCATION="FOREIGN"
            ;;

    esac


    # ==========================================================
    # WEEKLY1
    # ==========================================================

    read -r W1_COUNT W1_BYTES < <(
        scan_backup_dir "$SERVER_DIR/weekly1"
    )


    # ==========================================================
    # WEEKLY2
    # ==========================================================

    read -r W2_COUNT W2_BYTES < <(
        scan_backup_dir "$SERVER_DIR/weekly2"
    )


    # ==========================================================
    # HUMAN SIZE
    # ==============================================================

    W1_HUMAN=$(human_size "$W1_BYTES")
    W2_HUMAN=$(human_size "$W2_BYTES")


    # ==========================================================
    # BACKUP STATUS
    # ==========================================================

    if [ "$W1_COUNT" -gt 0 ] && [ "$W2_COUNT" -gt 0 ]; then

        STATUS="BOTH"

    elif [ "$W1_COUNT" -gt 0 ]; then

        STATUS="ONLY-WEEKLY1"

    elif [ "$W2_COUNT" -gt 0 ]; then

        STATUS="ONLY-WEEKLY2"

    else

        STATUS="NO-BACKUP"

    fi


    # ==========================================================
    # FORMATTED LINE
    # ==========================================================

    LINE=$(printf "%-10s %-16s %-12s %8s / %-9s %8s / %-9s %-16s" \
        "$SERVER" \
        "$IP" \
        "$LOCATION" \
        "$W1_COUNT" \
        "$W1_HUMAN" \
        "$W2_COUNT" \
        "$W2_HUMAN" \
        "$STATUS"
    )


    # ==========================================================
    # SAVE BY LOCATION
    # ==========================================================

    case "$LOCATION" in

        IRAN)
            echo "$LINE" >> "$TMP_IRAN"
            ;;

        FOREIGN)
            echo "$LINE" >> "$TMP_FOREIGN"
            ;;

        UNKNOWN)
            echo "$LINE" >> "$TMP_UNKNOWN"
            ;;

    esac

done


# ==============================================================
# PRINT TABLE FUNCTION
# ==============================================================

print_table() {

    local FILE="$1"

    printf "%-10s %-16s %-12s %21s %21s %-16s\n" \
        "SERVER" \
        "IP" \
        "LOCATION" \
        "WEEKLY1" \
        "WEEKLY2" \
        "STATUS"

    printf "%-10s %-16s %-12s %21s %21s %-16s\n" \
        "----------" \
        "----------------" \
        "------------" \
        "---------------------" \
        "---------------------" \
        "----------------"

    if [ -s "$FILE" ]; then
        cat "$FILE"
    else
        echo "None"
    fi
}


# ==============================================================
# IRAN
# ==============================================================

echo
echo "################################################################"
echo "#                           IRAN                               #"
echo "################################################################"

print_table "$TMP_IRAN"


# ==============================================================
# FOREIGN
# ==============================================================

echo
echo "################################################################"
echo "#                         FOREIGN                              #"
echo "################################################################"

print_table "$TMP_FOREIGN"


# ==============================================================
# UNKNOWN
# ==============================================================

echo
echo "################################################################"
echo "#                    UNKNOWN / NO GEOIP                       #"
echo "################################################################"

print_table "$TMP_UNKNOWN"


# ==============================================================
# TOTAL COUNTS
# ==============================================================

IRAN_TOTAL=$(wc -l < "$TMP_IRAN")
FOREIGN_TOTAL=$(wc -l < "$TMP_FOREIGN")
UNKNOWN_TOTAL=$(wc -l < "$TMP_UNKNOWN")


# ==============================================================
# IRAN STATUS
# ==============================================================

IRAN_BOTH=$(grep -c "BOTH" "$TMP_IRAN" 2>/dev/null || true)
IRAN_W1=$(grep -c "ONLY-WEEKLY1" "$TMP_IRAN" 2>/dev/null || true)
IRAN_W2=$(grep -c "ONLY-WEEKLY2" "$TMP_IRAN" 2>/dev/null || true)
IRAN_NONE=$(grep -c "NO-BACKUP" "$TMP_IRAN" 2>/dev/null || true)


# ==============================================================
# FOREIGN STATUS
# ==============================================================

FOREIGN_BOTH=$(grep -c "BOTH" "$TMP_FOREIGN" 2>/dev/null || true)
FOREIGN_W1=$(grep -c "ONLY-WEEKLY1" "$TMP_FOREIGN" 2>/dev/null || true)
FOREIGN_W2=$(grep -c "ONLY-WEEKLY2" "$TMP_FOREIGN" 2>/dev/null || true)
FOREIGN_NONE=$(grep -c "NO-BACKUP" "$TMP_FOREIGN" 2>/dev/null || true)


# ==============================================================
# TYPE COUNTS
# ==============================================================

IRAN_LH=$(grep -c "^lh" "$TMP_IRAN" 2>/dev/null || true)
IRAN_WH=$(grep -c "^wh" "$TMP_IRAN" 2>/dev/null || true)
IRAN_SONIC=$(grep -c "^sonic" "$TMP_IRAN" 2>/dev/null || true)

FOREIGN_LH=$(grep -c "^lh" "$TMP_FOREIGN" 2>/dev/null || true)
FOREIGN_WH=$(grep -c "^wh" "$TMP_FOREIGN" 2>/dev/null || true)
FOREIGN_SONIC=$(grep -c "^sonic" "$TMP_FOREIGN" 2>/dev/null || true)


# ==============================================================
# FINAL TASK SUMMARY
# ==============================================================

echo
echo
echo "################################################################"
echo "#                       TASK SUMMARY                           #"
echo "################################################################"


echo
echo "IRAN"
echo "--------------------------------------------------------------"
echo "Total servers  : $IRAN_TOTAL"
echo "LH             : $IRAN_LH"
echo "WH             : $IRAN_WH"
echo "SONIC          : $IRAN_SONIC"
echo
echo "Both           : $IRAN_BOTH"
echo "Only Weekly1   : $IRAN_W1"
echo "Only Weekly2   : $IRAN_W2"
echo "No Backup      : $IRAN_NONE"


echo
echo "FOREIGN"
echo "--------------------------------------------------------------"
echo "Total servers  : $FOREIGN_TOTAL"
echo "LH             : $FOREIGN_LH"
echo "WH             : $FOREIGN_WH"
echo "SONIC          : $FOREIGN_SONIC"
echo
echo "Both           : $FOREIGN_BOTH"
echo "Only Weekly1   : $FOREIGN_W1"
echo "Only Weekly2   : $FOREIGN_W2"
echo "No Backup      : $FOREIGN_NONE"


echo
echo "UNKNOWN"
echo "--------------------------------------------------------------"
echo "Total servers  : $UNKNOWN_TOTAL"


echo
echo "################################################################"
echo "Report finished: $(date)"
echo "################################################################"