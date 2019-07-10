/*
 * SWAMI KARUPPASWAMI THUNNAI
 * 
 * @author VISWESWARAN NAGASIVAM
 */

package api;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

/**
 *
 * @author Visweswaran
 */
public class ScanDir extends Thread{
    private final String folderLocation;
    private final JLabel label;
    private final JTable table;
    private final DefaultTableModel model;

    public ScanDir(String folderLocation, JLabel label, JTable table) {
        this.folderLocation = folderLocation;
        this.label = label;
        this.table = table;
        this.table.removeAll();
        this.model = (DefaultTableModel) this.table.getModel();
    }
    
    public void run()
    {
        try {
            Files.walk(Paths.get(folderLocation))
                    .filter(Files::isRegularFile)
                    .forEach(this::scan);
        } catch (IOException ex) {
            Logger.getLogger(ScanDir.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void scan(Path fileLocation)
    {
        label.setText(fileLocation.toString());
        try 
        {
            Document document = Jsoup.connect("http://127.0.0.1:5660/scan_file_for_yara").ignoreContentType(true).data("target", "all").data("file", fileLocation.toString()).post();
            JSONObject object = (JSONObject) new JSONParser().parse(document.text());
            boolean result = (boolean) object.get("message");
            if(result)
            {
                JSONArray array = (JSONArray) object.get("detections");
                for(Object o: array)
                {
                    JSONObject detection = (JSONObject) o;
                    model.addRow(new Object[]{fileLocation.toString(), detection.get("name"), detection.get("author"), detection.get("description")});
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(ScanFile.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ParseException ex) {
            Logger.getLogger(ScanFile.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
